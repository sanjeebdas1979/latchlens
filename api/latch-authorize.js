const LATCH_AUTHORIZE_URL =
  "https://onlatch.com/proxy/.well-known/latch-self/authorize";
const MAX_REQUEST_BYTES = 256 * 1024;
const MAX_RESPONSE_BYTES = 512 * 1024;
const UPSTREAM_TIMEOUT_MS = 10_000;
const FORBIDDEN_HYPOTHETICAL_HEADERS = new Set([
  "authorization",
  "cookie",
  "host",
  "content-length",
  "proxy-authorization",
  "x-forwarded-for",
  "x-forwarded-host",
  "x-forwarded-proto",
]);

function jsonResponse(value, status = 200) {
  return Response.json(value, {
    status,
    headers: {
      "cache-control": "no-store, max-age=0",
      "content-security-policy": "default-src 'none'",
      "x-content-type-options": "nosniff",
    },
  });
}

function isPlainObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function cleanText(value, maxLength) {
  return typeof value === "string" ? value.slice(0, maxLength) : undefined;
}

function sanitizeEvidence(value, depth = 0) {
  if (depth > 6 || value === null) return value === null ? null : "[truncated]";
  if (["string", "number", "boolean"].includes(typeof value)) {
    return typeof value === "string" ? value.slice(0, 4_000) : value;
  }
  if (Array.isArray(value)) {
    return value.slice(0, 100).map((item) => sanitizeEvidence(item, depth + 1));
  }
  if (!isPlainObject(value)) return String(value).slice(0, 4_000);

  const result = {};
  for (const [key, item] of Object.entries(value).slice(0, 100)) {
    if (/authorization|cookie|credential|secret|token|receipt/i.test(key)) continue;
    result[key] = sanitizeEvidence(item, depth + 1);
  }
  return result;
}

export function validateAuthorizeInput(input) {
  if (!isPlainObject(input)) {
    throw new Error("Request body must be a JSON object.");
  }

  const method = String(input.method || "").toUpperCase();
  if (!/^[A-Z]{1,16}$/.test(method)) {
    throw new Error("method must be an HTTP verb.");
  }

  const path = String(input.path || "");
  if (!path.startsWith("/") || path.length > 2_048 || /[\u0000-\u001f]/.test(path)) {
    throw new Error("path must be a valid relative request path.");
  }

  const headers = input.headers ?? {};
  if (!isPlainObject(headers) || Object.keys(headers).length > 50) {
    throw new Error("headers must be an object with at most 50 entries.");
  }

  const safeHeaders = Object.create(null);
  for (const [name, value] of Object.entries(headers)) {
    const lowerName = name.toLowerCase();
    if (
      !/^[!#$%&'*+.^_`|~0-9a-z-]+$/i.test(name) ||
      FORBIDDEN_HYPOTHETICAL_HEADERS.has(lowerName)
    ) {
      throw new Error("A hypothetical header is invalid or sensitive.");
    }
    if (typeof value !== "string" || value.length > 8_192) {
      throw new Error("Hypothetical header values must be short strings.");
    }
    safeHeaders[name] = value;
  }

  return {
    method,
    path,
    headers: safeHeaders,
    body: input.body ?? null,
  };
}

function validLatchAuthorization(value) {
  return (
    typeof value === "string" &&
    value.length <= 4_096 &&
    /^Bearer lat_[^\s]+$/.test(value)
  );
}

export async function POST(request) {
  const authorization = request.headers.get("authorization");
  if (!validLatchAuthorization(authorization)) {
    return jsonResponse({ error: "A valid Latch lat_ token is required." }, 401);
  }

  const announcedLength = Number(request.headers.get("content-length") || 0);
  if (announcedLength > MAX_REQUEST_BYTES) {
    return jsonResponse({ error: "Verification request is too large." }, 413);
  }

  let rawBody;
  try {
    rawBody = await request.text();
  } catch {
    return jsonResponse({ error: "Could not read the verification request." }, 400);
  }
  if (new TextEncoder().encode(rawBody).byteLength > MAX_REQUEST_BYTES) {
    return jsonResponse({ error: "Verification request is too large." }, 413);
  }

  let hypotheticalRequest;
  try {
    hypotheticalRequest = validateAuthorizeInput(JSON.parse(rawBody));
  } catch (error) {
    return jsonResponse(
      { error: error instanceof Error ? error.message : "Invalid JSON request." },
      400,
    );
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);

  try {
    const upstream = await fetch(LATCH_AUTHORIZE_URL, {
      method: "POST",
      headers: {
        authorization,
        "content-type": "application/json",
        accept: "application/json",
      },
      body: JSON.stringify(hypotheticalRequest),
      cache: "no-store",
      redirect: "error",
      signal: controller.signal,
    });

    const text = await upstream.text();
    if (new TextEncoder().encode(text).byteLength > MAX_RESPONSE_BYTES) {
      return jsonResponse({ error: "Latch returned an oversized response." }, 502);
    }

    let data = {};
    try {
      data = text ? JSON.parse(text) : {};
    } catch {
      return jsonResponse({ error: "Latch returned an invalid response." }, 502);
    }

    if (!upstream.ok) {
      const status = upstream.status === 401 || upstream.status === 403
        ? upstream.status
        : upstream.status === 429
          ? 429
          : 502;
      const message = upstream.status === 401
        ? "Latch rejected this token."
        : upstream.status === 403
          ? "This latch is disabled or expired."
          : upstream.status === 429
            ? "Latch rate-limited the verification."
            : "Latch authorization is temporarily unavailable.";
      return jsonResponse(
        {
          error: message,
          requestId: cleanText(data.requestId, 200),
        },
        status,
      );
    }

    if (data.decision !== "allow" && data.decision !== "deny") {
      return jsonResponse({ error: "Latch returned an unknown decision." }, 502);
    }

    return jsonResponse({
      decision: data.decision,
      requestId: cleanText(data.requestId, 200),
      deniedBy: cleanText(data.deniedBy, 500),
      deniedReason: cleanText(data.deniedReason, 2_000),
      filterResults: sanitizeEvidence(data.filterResults || []),
      receiptIssued: typeof data.receipt === "string" && data.receipt.length > 0,
    });
  } catch (error) {
    const timedOut = error instanceof Error && error.name === "AbortError";
    console.error("Latch authorize adapter failed", {
      kind: timedOut ? "timeout" : "network",
    });
    return jsonResponse(
      { error: timedOut ? "Latch authorization timed out." : "Could not reach Latch." },
      502,
    );
  } finally {
    clearTimeout(timeout);
  }
}

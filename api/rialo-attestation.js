const RIALO_DEVNET_RPC = "https://devnet.rialo.io:4101";
const NETWORK_NAME = "Rialo DevNet";
const REQUEST_SCHEMA = "latchlens.rialo-attestation.v1";
const EVIDENCE_SCHEMA = "latchlens.rialo-anchor-evidence.v1";
const MAX_REQUEST_BYTES = 64 * 1024;
const MAX_RESPONSE_BYTES = 512 * 1024;
const UPSTREAM_TIMEOUT_MS = 10_000;
const HASH_PATTERN = /^[a-f0-9]{64}$/;
const BASE58_PATTERN = /^[1-9A-HJ-NP-Za-km-z]+$/;
const DECIMAL_PATTERN = /^(0|[1-9][0-9]{0,19})$/;

export { RIALO_DEVNET_RPC };

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

function validBase58(value, minimum, maximum) {
  return (
    typeof value === "string" &&
    value.length >= minimum &&
    value.length <= maximum &&
    BASE58_PATTERN.test(value)
  );
}

function configuredProgramId() {
  const value = String(process.env.RIALO_ATTESTOR_PROGRAM_ID || "").trim();
  return validBase58(value, 32, 64) ? value : null;
}

function decimal(value, label) {
  const text = String(value ?? "");
  if (!DECIMAL_PATTERN.test(text)) {
    throw new Error(`${label} must be an unsigned decimal string.`);
  }
  const number = BigInt(text);
  if (number > 18_446_744_073_709_551_615n) {
    throw new Error(`${label} exceeds the u64 range.`);
  }
  return text;
}

function splitHashToU64(hash) {
  return Array.from({ length: 4 }, (_, index) =>
    BigInt("0x" + hash.slice(index * 16, index * 16 + 16)).toString(),
  );
}

export function validateAttestationRequest(input) {
  if (!isPlainObject(input)) {
    throw new Error("Request body must be a JSON object.");
  }
  if (!validBase58(input.signature, 64, 96)) {
    throw new Error("signature must be a valid Rialo transaction signature.");
  }
  if (!isPlainObject(input.expected)) {
    throw new Error("expected must contain the local receipt commitments.");
  }

  const expected = input.expected;
  if (expected.schema !== REQUEST_SCHEMA) {
    throw new Error("The attestation schema is not supported.");
  }
  if (!HASH_PATTERN.test(expected.policyHash || "")) {
    throw new Error("policyHash must be a lowercase SHA-256 value.");
  }
  if (!HASH_PATTERN.test(expected.reportHash || "")) {
    throw new Error("reportHash must be a lowercase SHA-256 value.");
  }

  const score = decimal(expected.score, "score");
  const passed = decimal(expected.passed, "passed");
  const failed = decimal(expected.failed, "failed");
  const generatedAt = decimal(expected.generatedAt, "generatedAt");
  if (BigInt(score) > 100n) {
    throw new Error("score must be between 0 and 100.");
  }
  if (BigInt(passed) + BigInt(failed) !== 14n) {
    throw new Error("passed and failed must describe all 14 attack cases.");
  }
  if (BigInt(generatedAt) === 0n) {
    throw new Error("generatedAt must be greater than zero.");
  }

  return {
    signature: input.signature,
    expected: {
      schema: REQUEST_SCHEMA,
      policyHash: expected.policyHash,
      reportHash: expected.reportHash,
      score,
      passed,
      failed,
      generatedAt,
    },
  };
}

function accountKeyText(value) {
  if (typeof value === "string") return value;
  if (isPlainObject(value) && typeof value.pubkey === "string") {
    return value.pubkey;
  }
  return "";
}

function instructionProgramId(instruction, accountKeys) {
  if (!isPlainObject(instruction)) return "";
  if (typeof instruction.programId === "string") return instruction.programId;
  if (isPlainObject(instruction.programId)) {
    return accountKeyText(instruction.programId);
  }
  if (Number.isInteger(instruction.programIdIndex)) {
    return accountKeys[instruction.programIdIndex] || "";
  }
  if (Number.isInteger(instruction.program_id_index)) {
    return accountKeys[instruction.program_id_index] || "";
  }
  return "";
}

function transactionContainsProgram(transaction, programId) {
  const message = transaction?.transaction?.message;
  if (!isPlainObject(message)) return false;
  const rawKeys = message.accountKeys || message.account_keys || [];
  const accountKeys = Array.isArray(rawKeys) ? rawKeys.map(accountKeyText) : [];
  const instructions = Array.isArray(message.instructions)
    ? message.instructions
    : [];
  return instructions.some(
    (instruction) => instructionProgramId(instruction, accountKeys) === programId,
  );
}

function successfulProgramFrames(logMessages, programId) {
  if (!Array.isArray(logMessages)) return [];
  const stack = [];
  const completed = [];

  for (const rawLine of logMessages) {
    if (typeof rawLine !== "string" || rawLine.length > 8_192) continue;
    let match = rawLine.match(/^Program ([1-9A-HJ-NP-Za-km-z]+) invoke \[(\d+)\]$/);
    if (match) {
      stack.push({ programId: match[1], logs: [] });
      continue;
    }

    match = rawLine.match(/^Program log: (.*)$/);
    if (match && stack.at(-1)?.programId === programId) {
      stack.at(-1).logs.push(match[1]);
      continue;
    }

    match = rawLine.match(/^Program ([1-9A-HJ-NP-Za-km-z]+) (success|failed(?::.*)?)$/);
    if (match) {
      const frame = stack.pop();
      if (
        frame?.programId === programId &&
        match[1] === programId &&
        match[2] === "success"
      ) {
        completed.push(frame.logs);
      }
    }
  }
  return completed;
}

function parseAttestationLogs(logs) {
  const requiredKeys = [
    "policy_hash_0",
    "policy_hash_1",
    "policy_hash_2",
    "policy_hash_3",
    "report_hash_0",
    "report_hash_1",
    "report_hash_2",
    "report_hash_3",
    "score",
    "passed",
    "failed",
    "generated_at",
  ];
  if (logs.filter((line) => line === "latchlens:v1").length !== 1) {
    throw new Error("The transaction does not contain one LatchLens v1 marker.");
  }
  if (!logs.includes("LatchLens assurance receipt recorded")) {
    throw new Error("The LatchLens program did not confirm the receipt write.");
  }

  const values = Object.create(null);
  for (const line of logs) {
    const match = line.match(/^([a-z0-9_]+)=(0|[1-9][0-9]{0,19})$/);
    if (!match || !requiredKeys.includes(match[1])) continue;
    if (Object.hasOwn(values, match[1])) {
      throw new Error(`The transaction repeats ${match[1]}.`);
    }
    values[match[1]] = decimal(match[2], match[1]);
  }
  for (const key of requiredKeys) {
    if (!Object.hasOwn(values, key)) {
      throw new Error(`The transaction is missing ${key}.`);
    }
  }
  return values;
}

function expectedLogValues(expected) {
  const policy = splitHashToU64(expected.policyHash);
  const report = splitHashToU64(expected.reportHash);
  return {
    policy_hash_0: policy[0],
    policy_hash_1: policy[1],
    policy_hash_2: policy[2],
    policy_hash_3: policy[3],
    report_hash_0: report[0],
    report_hash_1: report[1],
    report_hash_2: report[2],
    report_hash_3: report[3],
    score: expected.score,
    passed: expected.passed,
    failed: expected.failed,
    generated_at: expected.generatedAt,
  };
}

function assertAttestationMatches(values, expected) {
  const wanted = expectedLogValues(expected);
  for (const [key, value] of Object.entries(wanted)) {
    if (values[key] !== value) {
      throw new Error(`The confirmed transaction does not match ${key}.`);
    }
  }
}

function transactionSignatureIncluded(transaction, signature) {
  const signatures = transaction?.transaction?.signatures;
  return Array.isArray(signatures) && signatures.includes(signature);
}

function blockHeightText(transaction) {
  const value = transaction?.blockHeight ?? transaction?.block_height;
  if (
    (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) ||
    (typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value))
  ) {
    return String(value);
  }
  throw new Error("The RPC response does not include a valid block height.");
}

function blockTimeIso(transaction) {
  const value = transaction?.blockTime ?? transaction?.block_time;
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
    return null;
  }
  return new Date(value * 1_000).toISOString();
}

export function verifyAttestationTransaction(
  transaction,
  request,
  programId,
) {
  if (!isPlainObject(transaction)) {
    throw new Error("The transaction was not found on Rialo DevNet.");
  }
  const meta = transaction.meta;
  if (!isPlainObject(meta) || meta.err !== null) {
    throw new Error("The Rialo transaction did not complete successfully.");
  }
  if (!transactionSignatureIncluded(transaction, request.signature)) {
    throw new Error("The RPC transaction does not contain this signature.");
  }
  if (!transactionContainsProgram(transaction, programId)) {
    throw new Error("The configured LatchLens program was not invoked directly.");
  }

  const logMessages = meta.logMessages || meta.log_messages;
  const frames = successfulProgramFrames(logMessages, programId);
  if (frames.length !== 1) {
    throw new Error("Expected exactly one successful LatchLens program invocation.");
  }
  const values = parseAttestationLogs(frames[0]);
  assertAttestationMatches(values, request.expected);

  return {
    schema: EVIDENCE_SCHEMA,
    network: NETWORK_NAME,
    rpc: RIALO_DEVNET_RPC,
    programId,
    transactionSignature: request.signature,
    blockHeight: blockHeightText(transaction),
    blockTime: blockTimeIso(transaction),
    verifiedAt: new Date().toISOString(),
    policyHash: request.expected.policyHash,
    reportHash: request.expected.reportHash,
    score: request.expected.score,
    passed: request.expected.passed,
    failed: request.expected.failed,
    generatedAt: request.expected.generatedAt,
  };
}

export async function GET() {
  const programId = configuredProgramId();
  return jsonResponse({
    network: NETWORK_NAME,
    rpc: RIALO_DEVNET_RPC,
    ready: Boolean(programId),
    programId,
    mode: "public-read-only",
  });
}

export async function POST(request) {
  const programId = configuredProgramId();
  if (!programId) {
    return jsonResponse(
      { error: "The LatchLens DevNet program ID is not configured yet." },
      503,
    );
  }

  const announcedLength = Number(request.headers.get("content-length") || 0);
  if (announcedLength > MAX_REQUEST_BYTES) {
    return jsonResponse({ error: "Attestation request is too large." }, 413);
  }

  let rawBody;
  try {
    rawBody = await request.text();
  } catch {
    return jsonResponse({ error: "Could not read the attestation request." }, 400);
  }
  if (new TextEncoder().encode(rawBody).byteLength > MAX_REQUEST_BYTES) {
    return jsonResponse({ error: "Attestation request is too large." }, 413);
  }

  let input;
  try {
    input = validateAttestationRequest(JSON.parse(rawBody));
  } catch (error) {
    return jsonResponse(
      { error: error instanceof Error ? error.message : "Invalid JSON request." },
      400,
    );
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);
  try {
    const upstream = await fetch(RIALO_DEVNET_RPC, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: "latchlens-attestation",
        method: "getTransaction",
        params: [{ signature: input.signature }],
      }),
      cache: "no-store",
      redirect: "error",
      signal: controller.signal,
    });
    const text = await upstream.text();
    if (new TextEncoder().encode(text).byteLength > MAX_RESPONSE_BYTES) {
      return jsonResponse({ error: "Rialo returned an oversized response." }, 502);
    }

    let data;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      return jsonResponse({ error: "Rialo returned invalid JSON." }, 502);
    }
    if (!upstream.ok || !isPlainObject(data) || data.error) {
      return jsonResponse({ error: "Rialo DevNet could not return the transaction." }, 502);
    }
    if (data.result === null) {
      return jsonResponse(
        { error: "That transaction is not confirmed on Rialo DevNet yet." },
        404,
      );
    }

    try {
      return jsonResponse({
        valid: true,
        evidence: verifyAttestationTransaction(data.result, input, programId),
      });
    } catch (error) {
      return jsonResponse(
        {
          valid: false,
          error:
            error instanceof Error
              ? error.message
              : "The transaction does not match this receipt.",
        },
        422,
      );
    }
  } catch (error) {
    const timedOut = error instanceof Error && error.name === "AbortError";
    console.error("Rialo attestation lookup failed", {
      kind: timedOut ? "timeout" : "network",
    });
    return jsonResponse(
      {
        error: timedOut
          ? "Rialo DevNet verification timed out."
          : "Could not reach Rialo DevNet.",
      },
      502,
    );
  } finally {
    clearTimeout(timeout);
  }
}

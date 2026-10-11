const SEVERITY_WEIGHT = {
  critical: 24,
  high: 14,
  medium: 7,
  low: 3,
};

const ASSURANCE_RANK = {
  self_asserted: 0,
  hardware_attested: 1,
  managed_device: 2,
};

export const TEMPLATES = {
  unsafe: {
    label: "Unsafe starter",
    description: "A believable but dangerously incomplete policy.",
    policy: {
      name: "Support agent — draft",
      mutability: "open",
      inheritanceMode: "live",
      filters: [
        {
          type: "method",
          name: "Common verbs",
          allowed: ["GET", "POST", "DELETE"],
        },
        {
          type: "endpoint",
          name: "Block obvious admin paths",
          mode: "blocklist",
          patterns: ["/v1/admin/**"],
        },
        {
          type: "payload",
          name: "Token hint",
          rules: [
            {
              path: "max_tokens",
              operator: "less_than_or_equal",
              value: 32000,
            },
          ],
        },
      ],
    },
  },
  support: {
    label: "Support agent",
    description: "Tightly scoped model access with response redaction.",
    policy: {
      name: "Support agent — hardened",
      expiresAt: "2027-01-31T23:59:59Z",
      mutability: "attenuate_only",
      inheritanceMode: "live",
      filters: [
        {
          type: "method",
          name: "Read and complete",
          allowed: ["GET", "POST"],
        },
        {
          type: "endpoint",
          name: "Support endpoints only",
          mode: "allowlist",
          patterns: ["/v1/chat/completions", "/v1/models/*"],
        },
        {
          type: "payload",
          name: "Small models, bounded output",
          rules: [
            {
              path: "model",
              operator: "in",
              value: ["gpt-4o-mini", "claude-haiku-4-5"],
              reason: "Only approved support models are allowed.",
            },
            {
              path: "max_tokens",
              operator: "less_than_or_equal",
              value: 4096,
            },
          ],
        },
        {
          type: "body_size",
          name: "128 KB body cap",
          maxBytes: 131072,
        },
        {
          type: "rate_limit",
          name: "30 requests per minute",
          maxRequests: 30,
          windowSeconds: 60,
          keyBy: "latch",
        },
        {
          type: "time_window",
          name: "Weekday operations",
          timezone: "Asia/Kolkata",
          windows: [
            {
              days: [1, 2, 3, 4, 5],
              startTime: "08:00",
              endTime: "20:00",
            },
          ],
        },
        {
          type: "identity",
          name: "Enrolled support device",
          allowedAgentKids: ["kid_support_demo"],
          minAssurance: "self_asserted",
        },
        {
          type: "response",
          name: "Redact customer PII",
          rules: [
            {
              redactPaths: [
                "$.customers[*].ssn",
                "$.customers[*].email",
                "$.customer.phone",
              ],
              redactMode: "placeholder",
              maxResponseBytes: 1048576,
            },
          ],
        },
        {
          type: "spend_limit",
          name: "$5 daily ceiling",
          maxDailyCents: 500,
          pricing: "flat",
          costPerRequestCents: 1,
        },
      ],
    },
  },
  signer: {
    label: "Rialo signer",
    description: "Policy-gated Rialo transaction authorization.",
    policy: {
      name: "Rialo treasury signer",
      expiresAt: "2027-02-28T23:59:59Z",
      mutability: "locked",
      inheritanceMode: "live",
      filters: [
        {
          type: "method",
          name: "Signing endpoint only",
          allowed: ["POST"],
        },
        {
          type: "endpoint",
          name: "Transaction signing only",
          mode: "allowlist",
          patterns: ["/v1/transactions/sign"],
        },
        {
          type: "rialo_tx_signers",
          name: "Approved authorizers",
          signers: [
            "8bZ8w5Y2oQqvD8wqN2m8qXkYw7P9vD3tK1sR6nM4aL2",
          ],
        },
        {
          type: "payload",
          name: "Bound transfer",
          rules: [
            {
              path: "instruction",
              operator: "equals",
              value: "transfer",
            },
            {
              path: "amount_kelvin",
              operator: "less_than_or_equal",
              value: 1000000000,
            },
          ],
        },
        {
          type: "body_size",
          name: "32 KB body cap",
          maxBytes: 32768,
        },
        {
          type: "rate_limit",
          name: "Five signatures per hour",
          maxRequests: 5,
          windowSeconds: 3600,
          keyBy: "latch",
        },
        {
          type: "identity",
          name: "Bound operator device",
          allowedAgentKids: ["kid_treasury_demo"],
          minAssurance: "self_asserted",
        },
        {
          type: "spend_limit",
          name: "$20 daily ceiling",
          maxDailyCents: 2000,
          pricing: "flat",
          costPerRequestCents: 25,
        },
      ],
    },
  },
};

export function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

export function normalizePolicy(input) {
  const parsed = typeof input === "string" ? JSON.parse(input) : clone(input);
  if (Array.isArray(parsed)) {
    return {
      name: "Imported Latch pipeline",
      filters: parsed,
    };
  }
  if (!parsed || typeof parsed !== "object") {
    throw new Error("Policy must be a JSON object or a filter array.");
  }
  const filters = parsed.filters || parsed.pipeline;
  if (!Array.isArray(filters)) {
    throw new Error("Policy needs a filters or pipeline array.");
  }
  return {
    ...parsed,
    filters,
  };
}

function getByPath(value, path) {
  if (!path) return value;
  return String(path)
    .replace(/^\$\./, "")
    .split(".")
    .reduce((cursor, key) => {
      if (cursor === undefined || cursor === null) return undefined;
      return cursor[key];
    }, value);
}

function escapeRegex(value) {
  return value.replace(/[-/\\^$+?.()|[\]{}]/g, "\\$&");
}

export function globMatches(pattern, path) {
  const marker = "__DOUBLE_STAR__";
  const source = escapeRegex(String(pattern))
    .replace(/\*\*/g, marker)
    .replace(/\*/g, "[^/]*")
    .replace(new RegExp(marker, "g"), ".*");
  return new RegExp("^" + source + "$").test(String(path));
}

function conditionMatches(condition, request) {
  if (!condition) return true;
  if (
    Array.isArray(condition.methods) &&
    !condition.methods.includes(request.method)
  ) {
    return false;
  }
  if (
    condition.pathPrefix &&
    !String(request.path || "").startsWith(condition.pathPrefix)
  ) {
    return false;
  }
  if (
    typeof condition.hasBody === "boolean" &&
    condition.hasBody !== Boolean(request.body)
  ) {
    return false;
  }
  return true;
}

function payloadRulePasses(rule, body) {
  const actual = getByPath(body || {}, rule.path);
  const expected = rule.value;
  switch (rule.operator) {
    case "equals":
      return actual === expected;
    case "not_equals":
      return actual !== expected;
    case "in":
      return Array.isArray(expected) && expected.includes(actual);
    case "not_in":
      return Array.isArray(expected) && !expected.includes(actual);
    case "exists":
      return actual !== undefined;
    case "not_exists":
      return actual === undefined;
    case "greater_than":
      return (
        typeof actual === "number" &&
        typeof expected === "number" &&
        actual > expected
      );
    case "greater_than_or_equal":
      return (
        typeof actual === "number" &&
        typeof expected === "number" &&
        actual >= expected
      );
    case "less_than":
      return (
        typeof actual === "number" &&
        typeof expected === "number" &&
        actual < expected
      );
    case "less_than_or_equal":
      return (
        typeof actual === "number" &&
        typeof expected === "number" &&
        actual <= expected
      );
    case "matches":
      try {
        return new RegExp(String(expected)).test(String(actual ?? ""));
      } catch {
        return false;
      }
    case "max_length":
      return actual != null && actual.length <= expected;
    case "min_length":
      return actual != null && actual.length >= expected;
    case "required_fields":
      return (
        Array.isArray(expected) &&
        expected.every((field) => getByPath(actual || {}, field) !== undefined)
      );
    case "type_is":
      if (expected === "array") return Array.isArray(actual);
      if (expected === "null") return actual === null;
      return typeof actual === expected;
    default:
      return false;
  }
}

function minutes(value) {
  const parts = String(value || "00:00").split(":").map(Number);
  return parts[0] * 60 + parts[1];
}

function withinWindow(filter, request) {
  const day = Number.isInteger(request.day) ? request.day : new Date().getUTCDay();
  const time = request.time || "12:00";
  const point = minutes(time);
  return (filter.windows || []).some((window) => {
    if (!(window.days || []).includes(day)) return false;
    const start = minutes(window.startTime);
    const end = minutes(window.endTime);
    if (start <= end) return point >= start && point <= end;
    return point >= start || point <= end;
  });
}

function traceEntry(filter, outcome, detail) {
  return {
    filter: filter.name || filter.type,
    type: filter.type,
    outcome,
    detail,
  };
}

export function evaluateRequest(policyInput, requestInput) {
  const policy = normalizePolicy(policyInput);
  const request = {
    method: "POST",
    path: "/",
    body: {},
    headers: {},
    bodyBytes: 0,
    priorRequests: 0,
    currentSpendCents: 0,
    costCents: 0,
    ...requestInput,
  };
  const trace = [];

  for (const filter of policy.filters) {
    if (filter.disabled) {
      trace.push(traceEntry(filter, "skip", "Filter is disabled."));
      continue;
    }
    if (!conditionMatches(filter.condition, request)) {
      trace.push(traceEntry(filter, "skip", "Condition did not match."));
      continue;
    }

    let pass = true;
    let detail = "Passed.";

    if (filter.type === "method") {
      pass = (filter.allowed || []).includes(request.method);
      detail = pass
        ? request.method + " is allowed."
        : request.method + " is not allowed.";
    } else if (filter.type === "endpoint") {
      const matches = (filter.patterns || []).some((pattern) =>
        globMatches(pattern, request.path),
      );
      pass = filter.mode === "blocklist" ? !matches : matches;
      detail = pass
        ? "Path passed the " + (filter.mode || "allowlist") + "."
        : "Path failed the " + (filter.mode || "allowlist") + ".";
    } else if (filter.type === "payload") {
      const failed = (filter.rules || []).find(
        (rule) => !payloadRulePasses(rule, request.body),
      );
      pass = !failed;
      detail = pass
        ? "All payload assertions passed."
        : failed.reason ||
          "Payload rule failed at " + failed.path + " (" + failed.operator + ").";
    } else if (filter.type === "body_size") {
      pass = Number(request.bodyBytes || 0) <= Number(filter.maxBytes || 0);
      detail = pass
        ? "Body is within the cap."
        : "Body exceeds " + filter.maxBytes + " bytes.";
    } else if (filter.type === "time_window") {
      pass = withinWindow(filter, request);
      detail = pass
        ? "Request is inside an allowed window."
        : "Request is outside every allowed window.";
    } else if (filter.type === "ip_allowlist") {
      pass = (filter.allowed || []).includes(request.ip);
      detail = pass ? "Caller IP is allowed." : "Caller IP is not allowed.";
    } else if (filter.type === "header_requirement") {
      const failed = (filter.headers || []).find((header) => {
        const key = Object.keys(request.headers || {}).find(
          (name) => name.toLowerCase() === String(header.name).toLowerCase(),
        );
        if (!key) return true;
        if (!header.pattern) return false;
        try {
          return !new RegExp(header.pattern).test(request.headers[key]);
        } catch {
          return true;
        }
      });
      pass = !failed;
      detail = pass
        ? "Required headers are present."
        : "Missing or invalid header: " + failed.name + ".";
    } else if (filter.type === "identity") {
      const allowed = filter.allowedAgentKids || [];
      const identityAllowed =
        Boolean(request.agentKid) &&
        (allowed.includes("*") || allowed.includes(request.agentKid));
      const floor = ASSURANCE_RANK[filter.minAssurance || "self_asserted"] ?? 0;
      const actual = ASSURANCE_RANK[request.assurance || "self_asserted"] ?? 0;
      pass = identityAllowed && actual >= floor;
      detail = pass
        ? "Agent identity and assurance passed."
        : "Agent identity or assurance did not pass.";
    } else if (filter.type === "rate_limit") {
      pass = Number(request.priorRequests || 0) + 1 <= Number(filter.maxRequests);
      detail = pass ? "Request is under the rate cap." : "Rate cap exceeded.";
    } else if (filter.type === "spend_limit") {
      pass =
        Number(request.currentSpendCents || 0) +
          Number(request.costCents || 0) <=
        Number(filter.maxDailyCents || 0);
      detail = pass ? "Spend remains under the cap." : "Daily spend cap exceeded.";
    } else if (
      filter.type === "rialo_tx_signers" ||
      filter.type === "evm_tx_signers"
    ) {
      const signers = filter.signers || [];
      pass =
        signers.includes("*") ||
        (Boolean(request.authorizer) && signers.includes(request.authorizer));
      detail = pass
        ? "Transaction authorizer passed."
        : "Transaction authorizer did not pass.";
    } else if (
      filter.type === "response" ||
      filter.type === "custom_code" ||
      filter.type === "cedar"
    ) {
      trace.push(
        traceEntry(
          filter,
          "skip",
          filter.type === "response"
            ? "Response filter runs after upstream."
            : "Local mirror does not execute " + filter.type + ".",
        ),
      );
      continue;
    } else {
      trace.push(traceEntry(filter, "skip", "Unsupported local mirror filter."));
      continue;
    }

    trace.push(traceEntry(filter, pass ? "pass" : "deny", detail));
    if (!pass) {
      return {
        decision: "deny",
        deniedBy: filter.name || filter.type,
        reason: detail,
        trace,
      };
    }
  }

  return {
    decision: "allow",
    deniedBy: null,
    reason: "No filter denied the request.",
    trace,
  };
}

function firstFilter(policy, type) {
  return policy.filters.find((filter) => filter.type === type && !filter.disabled);
}

function baselineRequest(policy) {
  const methods = firstFilter(policy, "method");
  const endpoint = firstFilter(policy, "endpoint");
  const payload = firstFilter(policy, "payload");
  const identity = firstFilter(policy, "identity");
  const header = firstFilter(policy, "header_requirement");
  const signer =
    firstFilter(policy, "rialo_tx_signers") ||
    firstFilter(policy, "evm_tx_signers");
  const allowedPath =
    endpoint && endpoint.mode === "allowlist"
      ? (endpoint.patterns || []).find((item) => !item.includes("*")) ||
        String(endpoint.patterns?.[0] || "/").replace(/\*+/g, "item")
      : "/v1/chat/completions";
  const body = {};

  for (const rule of payload?.rules || []) {
    if (rule.operator === "equals") {
      setByPath(body, rule.path, rule.value);
    } else if (rule.operator === "in" && Array.isArray(rule.value)) {
      setByPath(body, rule.path, rule.value[0]);
    } else if (
      ["less_than", "less_than_or_equal"].includes(rule.operator) &&
      typeof rule.value === "number"
    ) {
      setByPath(body, rule.path, Math.max(0, rule.value - 1));
    } else if (rule.operator === "matches") {
      setByPath(body, rule.path, "1");
    }
  }

  const headers = {};
  for (const item of header?.headers || []) {
    headers[item.name] = item.name.toLowerCase().includes("tenant")
      ? "t_demo"
      : "demo";
  }

  return {
    method: methods?.allowed?.includes("POST")
      ? "POST"
      : methods?.allowed?.[0] || "POST",
    path: allowedPath,
    body,
    headers,
    bodyBytes: 512,
    day: 2,
    time: "12:00",
    ip: firstFilter(policy, "ip_allowlist")?.allowed?.[0],
    agentKid: identity?.allowedAgentKids?.find((item) => item !== "*"),
    assurance: identity?.minAssurance || "self_asserted",
    authorizer: signer?.signers?.find((item) => item !== "*"),
    priorRequests: 0,
    currentSpendCents: 0,
    costCents: 1,
  };
}

function setByPath(target, path, value) {
  const keys = String(path || "").replace(/^\$\./, "").split(".");
  let cursor = target;
  keys.forEach((key, index) => {
    if (index === keys.length - 1) {
      cursor[key] = value;
    } else {
      cursor[key] = cursor[key] || {};
      cursor = cursor[key];
    }
  });
}

function hasPiiRedaction(policy) {
  const filters = policy.filters.filter(
    (filter) => filter.type === "response" && !filter.disabled,
  );
  const paths = filters.flatMap((filter) =>
    (filter.rules || []).flatMap((rule) => rule.redactPaths || []),
  );
  return ["ssn", "email", "phone"].some((needle) =>
    paths.some((path) => String(path).toLowerCase().includes(needle)),
  );
}

function signerIsWildcard(policy) {
  return policy.filters.some(
    (filter) =>
      ["rialo_tx_signers", "evm_tx_signers"].includes(filter.type) &&
      !filter.disabled &&
      (filter.signers || []).includes("*"),
  );
}

export function buildTestDeck(policyInput) {
  const policy = normalizePolicy(policyInput);
  const baseline = baselineRequest(policy);
  return [
    {
      id: "intended-call",
      title: "Intended request remains usable",
      category: "Usability",
      severity: "medium",
      expected: "allow",
      request: baseline,
      remediation:
        "Review the first denying filter so the intended least-privilege path still works.",
    },
    {
      id: "destructive-delete",
      title: "Destructive DELETE is blocked",
      category: "Method boundary",
      severity: "critical",
      expected: "deny",
      request: {
        ...baseline,
        method: "DELETE",
        path: "/v1/customers/c_123",
      },
      remediation: "Use a method allowlist and omit DELETE.",
    },
    {
      id: "admin-export",
      title: "Unlisted admin export is blocked",
      category: "Endpoint scope",
      severity: "critical",
      expected: "deny",
      request: {
        ...baseline,
        method: "POST",
        path: "/v1/admin/export",
      },
      remediation:
        "Prefer a narrow endpoint allowlist; blocklists cannot enumerate every sensitive route.",
    },
    {
      id: "path-confusion",
      title: "Encoded path-confusion attempt is blocked",
      category: "Endpoint scope",
      severity: "high",
      expected: "deny",
      request: {
        ...baseline,
        method: "POST",
        path: "/v1/chat/%2e%2e/admin/export",
      },
      remediation:
        "Normalize request paths before glob matching and keep the allowlist exact.",
    },
    {
      id: "oversized-body",
      title: "Two-megabyte body is blocked",
      category: "Resource control",
      severity: "high",
      expected: "deny",
      request: {
        ...baseline,
        bodyBytes: 2 * 1024 * 1024,
      },
      remediation: "Add a body_size filter with a workload-appropriate cap.",
    },
    {
      id: "model-escalation",
      title: "Unapproved model escalation is blocked",
      category: "Payload",
      severity: "high",
      expected: "deny",
      request: {
        ...baseline,
        body: {
          ...baseline.body,
          model: "unapproved-frontier-model",
        },
      },
      remediation: "Allowlist approved models with a payload rule.",
    },
    {
      id: "token-explosion",
      title: "Extreme output request is blocked",
      category: "Payload",
      severity: "high",
      expected: "deny",
      request: {
        ...baseline,
        body: {
          ...baseline.body,
          max_tokens: 100000,
        },
      },
      remediation: "Cap max_tokens with a numeric payload assertion.",
    },
    {
      id: "identity-theft",
      title: "Stolen token without agent identity is blocked",
      category: "Identity",
      severity: "critical",
      expected: "deny",
      request: {
        ...baseline,
        agentKid: null,
      },
      remediation:
        "Bind the latch to enrolled agent keys with the identity filter.",
    },
    {
      id: "off-hours",
      title: "Sunday 03:00 call is blocked",
      category: "Time boundary",
      severity: "medium",
      expected: "deny",
      request: {
        ...baseline,
        day: 0,
        time: "03:00",
      },
      remediation: "Add an explicit timezone-aware time_window filter.",
    },
    {
      id: "rate-flood",
      title: "Burst after 100 requests is blocked",
      category: "Velocity",
      severity: "high",
      expected: "deny",
      request: {
        ...baseline,
        priorRequests: 100,
      },
      remediation: "Add a durable rate_limit keyed to the correct actor.",
    },
    {
      id: "spend-burst",
      title: "$250 incremental spend is blocked",
      category: "Spend",
      severity: "critical",
      expected: "deny",
      request: {
        ...baseline,
        costCents: 25000,
      },
      remediation: "Add a spend_limit below the maximum acceptable loss.",
    },
    {
      id: "pii-response",
      title: "PII is redacted from upstream responses",
      category: "Data egress",
      severity: "critical",
      expected: "custom",
      custom: () => hasPiiRedaction(policy),
      remediation:
        "Add a response filter that redacts email, phone and regulated identifiers.",
    },
    {
      id: "delegation-narrows",
      title: "Child delegation cannot widen authority",
      category: "Delegation",
      severity: "high",
      expected: "custom",
      custom: () =>
        ["attenuate_only", "locked"].includes(policy.mutability || ""),
      remediation:
        "Set child mutability to attenuate_only or locked and resolve inheritance live.",
    },
    {
      id: "signer-wildcard",
      title: "Transaction signing is not permissionless",
      category: "Signing",
      severity: "critical",
      expected: "custom",
      custom: () => !signerIsWildcard(policy),
      remediation:
        "Replace the '*' signer with explicit Rialo or EVM authorizer keys.",
    },
  ];
}

const LIVE_AUTHORIZE_CASES = new Set([
  "intended-call",
  "destructive-delete",
  "admin-export",
  "path-confusion",
  "model-escalation",
  "token-explosion",
]);

const LIVE_SKIP_REASONS = {
  "oversized-body":
    "Skipped to avoid sending a synthetic multi-megabyte payload through the browser adapter.",
  "identity-theft":
    "The authorize endpoint derives identity from the live latch context; it does not accept a simulated agent key.",
  "off-hours":
    "The authorize endpoint evaluates the current clock; it does not accept a simulated day or time.",
  "rate-flood":
    "A dry run cannot safely manufacture one hundred prior requests.",
  "spend-burst":
    "The authorize request has no synthetic cost field; live budget state remains authoritative.",
  "pii-response":
    "Response redaction runs after an upstream response, while authorize never calls the upstream.",
  "delegation-narrows":
    "Delegation mutability is a policy-structure assertion, not one hypothetical HTTP request.",
  "signer-wildcard":
    "Signer scope is checked structurally because authorize does not accept a simulated authorizer field.",
};

function authorizeRequest(request) {
  return {
    method: request.method,
    path: request.path,
    headers: request.headers || {},
    body: request.body ?? {},
  };
}

export function buildLiveVerificationPlan(policyInput) {
  const deck = buildTestDeck(policyInput);
  return {
    runnable: deck
      .filter((test) => LIVE_AUTHORIZE_CASES.has(test.id))
      .map((test) => ({
        id: test.id,
        title: test.title,
        category: test.category,
        severity: test.severity,
        expected: test.expected,
        request: authorizeRequest(test.request),
      })),
    skipped: deck
      .filter((test) => !LIVE_AUTHORIZE_CASES.has(test.id))
      .map((test) => ({
        id: test.id,
        title: test.title,
        reason:
          LIVE_SKIP_REASONS[test.id] ||
          "This scenario is verified by the local structural engine.",
      })),
  };
}

export function runSuite(policyInput) {
  const policy = normalizePolicy(policyInput);
  return buildTestDeck(policy).map((test) => {
    if (test.expected === "custom") {
      const passed = Boolean(test.custom());
      return {
        ...test,
        status: passed ? "pass" : "fail",
        actual: passed ? "protected" : "exposed",
        trace: [],
      };
    }
    const result = evaluateRequest(policy, test.request);
    const passed = result.decision === test.expected;
    return {
      ...test,
      status: passed ? "pass" : "fail",
      actual: result.decision,
      trace: result.trace,
      deniedBy: result.deniedBy,
      reason: result.reason,
    };
  });
}

function finding(code, title, severity, detail, fix, source) {
  return {
    code,
    title,
    severity,
    detail,
    fix,
    source,
  };
}

function structuralFindings(policy, now = Date.now()) {
  const findings = [];
  const method = firstFilter(policy, "method");
  const endpoint = firstFilter(policy, "endpoint");
  const identity = firstFilter(policy, "identity");
  const response = firstFilter(policy, "response");
  const bodySize = firstFilter(policy, "body_size");
  const rate = firstFilter(policy, "rate_limit");
  const spend = firstFilter(policy, "spend_limit");
  const payload = firstFilter(policy, "payload");

  if (!method) {
    findings.push(
      finding(
        "METHOD_MISSING",
        "No HTTP method boundary",
        "critical",
        "Any upstream verb may reach the credential.",
        "Add a method allowlist containing only required verbs.",
        "structure",
      ),
    );
  } else if (
    (method.allowed || []).some((verb) =>
      ["DELETE", "PUT", "PATCH"].includes(verb),
    )
  ) {
    findings.push(
      finding(
        "METHOD_DESTRUCTIVE",
        "Destructive verbs are enabled",
        "high",
        "DELETE, PUT or PATCH creates a larger blast radius.",
        "Remove every verb the agent does not strictly need.",
        "structure",
      ),
    );
  }

  if (!endpoint) {
    findings.push(
      finding(
        "ENDPOINT_MISSING",
        "No endpoint boundary",
        "critical",
        "The latch can reach every path on its upstream.",
        "Add a narrow endpoint allowlist.",
        "structure",
      ),
    );
  } else if (endpoint.mode !== "allowlist") {
    findings.push(
      finding(
        "ENDPOINT_BLOCKLIST",
        "Endpoint policy relies on a blocklist",
        "high",
        "A new or overlooked sensitive route remains reachable.",
        "Replace the blocklist with a least-privilege allowlist.",
        "structure",
      ),
    );
  } else if ((endpoint.patterns || []).some((pattern) => pattern === "/**")) {
    findings.push(
      finding(
        "ENDPOINT_GLOBAL",
        "Global endpoint wildcard",
        "critical",
        "The allowlist effectively permits the whole upstream.",
        "Replace /** with exact product routes.",
        "structure",
      ),
    );
  }

  if (!identity) {
    findings.push(
      finding(
        "IDENTITY_MISSING",
        "Token is not bound to an agent identity",
        "high",
        "Possession of the latch token is enough to use its authority.",
        "Add an identity filter with explicit allowed agent key IDs.",
        "structure",
      ),
    );
  } else if (
    ["hardware_attested", "managed_device"].includes(identity.minAssurance)
  ) {
    findings.push(
      finding(
        "ASSURANCE_UNAVAILABLE",
        "Assurance floor may fail every request",
        "medium",
        "Current Latch documentation says enrolled devices report self_asserted until attestation verification is available.",
        "Use self_asserted for the current environment, then raise the floor when verified attestation is supported.",
        "structure",
      ),
    );
  }

  if (!response) {
    findings.push(
      finding(
        "RESPONSE_UNFILTERED",
        "Upstream responses are uncontained",
        "high",
        "Sensitive fields and oversized responses can return to the agent.",
        "Add response redaction paths and a maximum response size.",
        "structure",
      ),
    );
  }
  if (!bodySize) {
    findings.push(
      finding(
        "BODY_UNBOUNDED",
        "Request body has no size cap",
        "medium",
        "Runaway or hostile payloads can consume excessive resources.",
        "Add a body_size filter.",
        "structure",
      ),
    );
  }
  if (!rate) {
    findings.push(
      finding(
        "RATE_UNBOUNDED",
        "No request velocity limit",
        "medium",
        "A loop can spend or mutate at machine speed.",
        "Add a rate_limit keyed to the latch, IP or end user.",
        "structure",
      ),
    );
  }
  if (!spend) {
    findings.push(
      finding(
        "SPEND_UNBOUNDED",
        "No daily spend ceiling",
        "critical",
        "A valid token can create uncapped cost.",
        "Add a spend_limit with model or flat pricing.",
        "structure",
      ),
    );
  }
  if (!payload) {
    findings.push(
      finding(
        "PAYLOAD_UNSCOPED",
        "Request semantics are not constrained",
        "high",
        "Allowed endpoints may still receive dangerous models, amounts or actions.",
        "Add payload assertions for the fields that carry risk.",
        "structure",
      ),
    );
  }

  if (!policy.expiresAt) {
    findings.push(
      finding(
        "NO_EXPIRY",
        "Authority has no explicit expiry",
        "medium",
        "The token can outlive the task that justified it.",
        "Set an expiry close to the task horizon.",
        "structure",
      ),
    );
  } else if (new Date(policy.expiresAt).getTime() <= now) {
    findings.push(
      finding(
        "EXPIRED",
        "Policy is already expired",
        "high",
        "The configured expiry is in the past.",
        "Issue a new narrowly scoped latch instead of silently extending this one.",
        "structure",
      ),
    );
  }

  if (!["attenuate_only", "locked"].includes(policy.mutability || "")) {
    findings.push(
      finding(
        "DELEGATION_WIDENS",
        "Delegated children may widen authority",
        "high",
        "The policy does not assert attenuation-only inheritance.",
        "Use attenuate_only or locked child mutability.",
        "structure",
      ),
    );
  }

  for (const filter of policy.filters) {
    if (
      filter.type === "custom_code" &&
      filter.language === "javascript" &&
      !filter.disabled
    ) {
      findings.push(
        finding(
          "JS_OUTSIDE_ENCLAVE",
          "JavaScript policy is not enclave-evaluated",
          "medium",
          "Latch documents Rust/WASM as the in-enclave custom-code path.",
          "Use Rust/WASM for rules that require confidential evaluation.",
          "structure",
        ),
      );
    }
    if (
      ["rialo_tx_signers", "evm_tx_signers"].includes(filter.type) &&
      (filter.signers || []).includes("*") &&
      !filter.disabled
    ) {
      findings.push(
        finding(
          "SIGNER_WILDCARD",
          "Transaction signer is permissionless",
          "critical",
          "Any caller can authorize a transaction if the remaining filters pass.",
          "Allowlist explicit authorizer keys.",
          "structure",
        ),
      );
    }
  }

  return findings;
}

function dedupeFindings(findings) {
  const seen = new Set();
  return findings.filter((item) => {
    if (seen.has(item.code)) return false;
    seen.add(item.code);
    return true;
  });
}

export function analyzePolicy(policyInput, options) {
  const policy = normalizePolicy(policyInput);
  const tests = runSuite(policy);
  const requestedNow = options?.now;
  const parsedNow =
    typeof requestedNow === "number"
      ? requestedNow
      : requestedNow
        ? new Date(requestedNow).getTime()
        : Date.now();
  const findings = structuralFindings(
    policy,
    Number.isFinite(parsedNow) ? parsedNow : Date.now(),
  );

  for (const test of tests.filter((item) => item.status === "fail")) {
    findings.push(
      finding(
        "TEST_" + test.id.toUpperCase().replace(/-/g, "_"),
        test.title,
        test.severity,
        test.expected === "allow"
          ? "A legitimate baseline request was denied by the current policy."
          : "The adversarial scenario was not stopped by the local policy mirror.",
        test.remediation,
        "test",
      ),
    );
  }

  const unique = dedupeFindings(findings);
  const penalty = unique.reduce(
    (total, item) => total + (SEVERITY_WEIGHT[item.severity] || 0),
    0,
  );
  const score = Math.max(0, 100 - penalty);
  const counts = {
    critical: unique.filter((item) => item.severity === "critical").length,
    high: unique.filter((item) => item.severity === "high").length,
    medium: unique.filter((item) => item.severity === "medium").length,
    low: unique.filter((item) => item.severity === "low").length,
  };
  const grade =
    score >= 90
      ? "Ready"
      : score >= 75
        ? "Review"
        : score >= 50
          ? "Risky"
          : "Exposed";

  return {
    policy,
    score,
    grade,
    counts,
    findings: unique,
    tests,
    passed: tests.filter((item) => item.status === "pass").length,
    failed: tests.filter((item) => item.status === "fail").length,
  };
}

function hasType(policy, type) {
  return policy.filters.some((filter) => filter.type === type && !filter.disabled);
}

export function hardenPolicy(policyInput) {
  const policy = normalizePolicy(policyInput);
  const hardened = clone(policy);
  hardened.mutability = "attenuate_only";
  hardened.inheritanceMode = hardened.inheritanceMode || "live";
  if (!hardened.expiresAt) {
    const expiry = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
    hardened.expiresAt = expiry.toISOString();
  }

  const method = firstFilter(hardened, "method");
  if (!method) {
    hardened.filters.unshift({
      type: "method",
      name: "Least-privilege methods",
      allowed: ["GET", "POST"],
    });
  } else {
    method.allowed = (method.allowed || []).filter((verb) =>
      ["GET", "POST", "HEAD"].includes(verb),
    );
    if (!method.allowed.length) method.allowed = ["GET", "POST"];
  }

  if (!hasType(hardened, "body_size")) {
    hardened.filters.push({
      type: "body_size",
      name: "128 KB request cap",
      maxBytes: 131072,
    });
  }
  if (!hasType(hardened, "rate_limit")) {
    hardened.filters.push({
      type: "rate_limit",
      name: "30 requests per minute",
      maxRequests: 30,
      windowSeconds: 60,
      keyBy: "latch",
    });
  }
  if (!hasType(hardened, "spend_limit")) {
    hardened.filters.push({
      type: "spend_limit",
      name: "$10 daily ceiling — review",
      maxDailyCents: 1000,
      pricing: "flat",
      costPerRequestCents: 1,
    });
  }
  if (!hasType(hardened, "identity")) {
    hardened.filters.push({
      type: "identity",
      name: "Replace with enrolled agent key",
      allowedAgentKids: ["kid_replace_me"],
      minAssurance: "self_asserted",
    });
  }
  if (!hasType(hardened, "response")) {
    hardened.filters.push({
      type: "response",
      name: "Common PII redaction",
      rules: [
        {
          redactPaths: [
            "$.customers[*].ssn",
            "$.customers[*].email",
            "$.customer.phone",
          ],
          redactMode: "placeholder",
          maxResponseBytes: 1048576,
        },
      ],
    });
  }
  if (!hasType(hardened, "payload")) {
    hardened.filters.push({
      type: "payload",
      name: "Review semantic limits",
      rules: [
        {
          path: "max_tokens",
          operator: "less_than_or_equal",
          value: 4096,
        },
      ],
    });
  }

  for (const filter of hardened.filters) {
    if (
      ["rialo_tx_signers", "evm_tx_signers"].includes(filter.type) &&
      (filter.signers || []).includes("*")
    ) {
      filter.signers = [];
      filter.name = (filter.name || filter.type) + " — add authorizers";
    }
  }
  return hardened;
}

export function stableStringify(value) {
  if (Array.isArray(value)) {
    return "[" + value.map(stableStringify).join(",") + "]";
  }
  if (value && typeof value === "object") {
    return (
      "{" +
      Object.keys(value)
        .sort()
        .map(
          (key) => JSON.stringify(key) + ":" + stableStringify(value[key]),
        )
        .join(",") +
      "}"
    );
  }
  return JSON.stringify(value);
}

async function sha256Hex(value) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export const RIALO_DEVNET = Object.freeze({
  name: "Rialo DevNet",
  rpc: "https://devnet.rialo.io:4101",
});

const RECEIPT_SCHEMA_V1 = "latchlens.policy-proof.v1";
const RECEIPT_SCHEMA_V2 = "latchlens.policy-proof.v2";
const ATTESTATION_SCHEMA = "latchlens.rialo-attestation.v1";
const ANCHOR_EVIDENCE_SCHEMA = "latchlens.rialo-anchor-evidence.v1";
const HASH_PATTERN = /^[a-f0-9]{64}$/;
const BASE58_PATTERN = /^[1-9A-HJ-NP-Za-km-z]+$/;

export function splitHashToU64(hash) {
  if (!HASH_PATTERN.test(hash || "")) {
    throw new Error("A Rialo commitment must be a 64-character SHA-256 hash.");
  }
  return Array.from({ length: 4 }, (_, index) =>
    BigInt("0x" + hash.slice(index * 16, index * 16 + 16)).toString(),
  );
}

function generatedAtMilliseconds(receipt) {
  const timestamp = Date.parse(receipt.generatedAt);
  if (!Number.isSafeInteger(timestamp) || timestamp <= 0) {
    throw new Error("The receipt has an invalid generation time.");
  }
  return String(timestamp);
}

function buildAttestationArgs(receipt) {
  const policyLimbs = splitHashToU64(receipt.policyHash);
  const reportLimbs = splitHashToU64(receipt.reportHash);
  return {
    policy_hash_0: policyLimbs[0],
    policy_hash_1: policyLimbs[1],
    policy_hash_2: policyLimbs[2],
    policy_hash_3: policyLimbs[3],
    report_hash_0: reportLimbs[0],
    report_hash_1: reportLimbs[1],
    report_hash_2: reportLimbs[2],
    report_hash_3: reportLimbs[3],
    score: String(receipt.score),
    passed: String(receipt.passed),
    failed: String(receipt.failed),
    generated_at: generatedAtMilliseconds(receipt),
  };
}

export async function createReceipt(analysis, liveVerification) {
  const generatedAt = new Date().toISOString();
  const liveSummary = liveVerification
    ? {
        schema: liveVerification.schema,
        endpoint: liveVerification.endpoint,
        verifiedAt: liveVerification.verifiedAt,
        checked: liveVerification.checked,
        matched: liveVerification.matched,
        mismatched: liveVerification.mismatched,
        skipped: liveVerification.skipped,
        evidenceHash: await sha256Hex(stableStringify(liveVerification)),
      }
    : null;
  const core = {
    schema: RECEIPT_SCHEMA_V2,
    generatedAt,
    engine: "LatchLens local mirror 0.4.0",
    mode: liveSummary ? "latch-authorize-compared" : "local-draft",
    policyName: analysis.policy.name || "Imported policy",
    policyHash: await sha256Hex(stableStringify(analysis.policy)),
    score: analysis.score,
    grade: analysis.grade,
    passed: analysis.passed,
    failed: analysis.failed,
    findingCodes: analysis.findings.map((item) => item.code).sort(),
    ...(liveSummary ? { liveVerification: liveSummary } : {}),
  };
  return {
    ...core,
    reportHash: await sha256Hex(stableStringify(core)),
    rialo: {
      status: "not-anchored",
      network: RIALO_DEVNET.name,
      rpc: RIALO_DEVNET.rpc,
      program: "LatchLensAttestor — deployment required",
    },
  };
}

export function buildRialoPayload(receipt) {
  if (receipt.schema === RECEIPT_SCHEMA_V1) {
    return {
      network: "Rialo DevNet",
      program: "LatchLensAttestor",
      instruction: "attest_policy_report",
      args: {
        report_hash: receipt.reportHash,
        policy_hash: receipt.policyHash,
        score: receipt.score,
        passed: receipt.passed,
        failed: receipt.failed,
        generated_at: receipt.generatedAt,
      },
      status: "prepared-not-submitted",
    };
  }

  if (receipt.schema !== RECEIPT_SCHEMA_V2) {
    throw new Error("Unsupported LatchLens receipt schema.");
  }

  const anchored = receipt.rialo?.status === "anchored";
  return {
    schema: ATTESTATION_SCHEMA,
    network: RIALO_DEVNET.name,
    rpc: RIALO_DEVNET.rpc,
    program: "LatchLensAttestor",
    programId: anchored ? receipt.rialo.programId : null,
    instruction: "attest_policy_report",
    args: buildAttestationArgs(receipt),
    commitments: {
      policyHash: receipt.policyHash,
      reportHash: receipt.reportHash,
    },
    status: anchored ? "submitted-confirmed" : "prepared-not-submitted",
    ...(anchored
      ? {
          transaction: {
            signature: receipt.rialo.transactionSignature,
            blockHeight: receipt.rialo.blockHeight,
            verifiedAt: receipt.rialo.verifiedAt,
          },
        }
      : {}),
  };
}

export function buildRialoAnchorBundle(receipt) {
  if (receipt.schema !== RECEIPT_SCHEMA_V2) {
    throw new Error("Generate a fresh v0.4 receipt before preparing an anchor.");
  }
  const payload = buildRialoPayload({
    ...receipt,
    rialo: {
      status: "not-anchored",
      network: RIALO_DEVNET.name,
      rpc: RIALO_DEVNET.rpc,
    },
  });
  return {
    schema: "latchlens.rialo-anchor-request.v1",
    preparedAt: new Date().toISOString(),
    network: {
      name: RIALO_DEVNET.name,
      rpc: RIALO_DEVNET.rpc,
    },
    program: {
      name: "LatchLensAttestor",
      instruction: payload.instruction,
      programId: null,
    },
    receipt: {
      schema: receipt.schema,
      policyHash: receipt.policyHash,
      reportHash: receipt.reportHash,
      score: receipt.score,
      passed: receipt.passed,
      failed: receipt.failed,
      generatedAt: receipt.generatedAt,
    },
    invocation: {
      args: payload.args,
    },
    safety: {
      containsPrivateKey: false,
      signingRequired: true,
      note: "Sign with an owner-controlled Rialo DevNet wallet; never upload a seed phrase to LatchLens.",
    },
  };
}

export function buildRialoVerificationRequest(receipt, signature) {
  const normalizedSignature = String(signature || "").trim();
  if (
    normalizedSignature.length < 64 ||
    normalizedSignature.length > 96 ||
    !BASE58_PATTERN.test(normalizedSignature)
  ) {
    throw new Error("Enter a valid Rialo transaction signature.");
  }
  if (receipt.schema !== RECEIPT_SCHEMA_V2) {
    throw new Error("Generate a fresh v0.4 receipt before verifying an anchor.");
  }
  return {
    signature: normalizedSignature,
    expected: {
      schema: ATTESTATION_SCHEMA,
      policyHash: receipt.policyHash,
      reportHash: receipt.reportHash,
      score: String(receipt.score),
      passed: String(receipt.passed),
      failed: String(receipt.failed),
      generatedAt: generatedAtMilliseconds(receipt),
    },
  };
}

function anchoredEvidenceMatches(receipt, evidence) {
  if (!evidence || typeof evidence !== "object" || Array.isArray(evidence)) {
    return false;
  }
  const expected = buildAttestationArgs(receipt);
  return (
    evidence.schema === ANCHOR_EVIDENCE_SCHEMA &&
    evidence.network === RIALO_DEVNET.name &&
    evidence.rpc === RIALO_DEVNET.rpc &&
    typeof evidence.programId === "string" &&
    evidence.programId.length >= 32 &&
    evidence.programId.length <= 64 &&
    BASE58_PATTERN.test(evidence.programId) &&
    typeof evidence.transactionSignature === "string" &&
    evidence.transactionSignature.length >= 64 &&
    evidence.transactionSignature.length <= 96 &&
    BASE58_PATTERN.test(evidence.transactionSignature) &&
    /^(0|[1-9][0-9]*)$/.test(String(evidence.blockHeight ?? "")) &&
    evidence.policyHash === receipt.policyHash &&
    evidence.reportHash === receipt.reportHash &&
    String(evidence.score) === expected.score &&
    String(evidence.passed) === expected.passed &&
    String(evidence.failed) === expected.failed &&
    String(evidence.generatedAt) === expected.generated_at &&
    typeof evidence.verifiedAt === "string" &&
    Number.isFinite(Date.parse(evidence.verifiedAt))
  );
}

export function attachRialoAttestation(receiptInput, evidenceInput) {
  const receipt = clone(receiptInput);
  const evidence = clone(evidenceInput);
  if (receipt.schema !== RECEIPT_SCHEMA_V2) {
    throw new Error("Only v0.4 receipts can carry a DevNet anchor.");
  }
  if (!anchoredEvidenceMatches(receipt, evidence)) {
    throw new Error("The DevNet evidence does not match this receipt.");
  }
  receipt.rialo = {
    status: "anchored",
    network: RIALO_DEVNET.name,
    rpc: RIALO_DEVNET.rpc,
    program: "LatchLensAttestor",
    programId: evidence.programId,
    transactionSignature: evidence.transactionSignature,
    blockHeight: String(evidence.blockHeight),
    verifiedAt: evidence.verifiedAt,
    evidence,
  };
  return receipt;
}

function reportAnalysis(analysis) {
  return clone({
    score: analysis.score,
    grade: analysis.grade,
    counts: analysis.counts,
    findings: analysis.findings,
    tests: analysis.tests.map((test) => ({
      id: test.id,
      title: test.title,
      category: test.category,
      severity: test.severity,
      status: test.status,
      actual: test.actual,
      deniedBy: test.deniedBy,
      reason: test.reason,
      remediation: test.remediation,
      trace: test.trace,
    })),
  });
}

export function buildAssuranceReport(
  analysis,
  receipt,
  rialoPayload,
  liveVerification,
) {
  return {
    receipt,
    analysis: reportAnalysis(analysis),
    ...(liveVerification ? { liveVerification } : {}),
    rialoPayload,
  };
}

function verificationCheck(id, label, passed, detail) {
  return { id, label, passed, detail };
}

function sameValue(left, right) {
  return stableStringify(left) === stableStringify(right);
}

export async function verifyAssuranceReport(reportInput, policyInput, options) {
  const report =
    typeof reportInput === "string" ? JSON.parse(reportInput) : clone(reportInput);
  if (!report || typeof report !== "object" || Array.isArray(report)) {
    throw new Error("The selected file is not a LatchLens assurance report.");
  }

  const receipt = report.receipt;
  if (!receipt || typeof receipt !== "object" || Array.isArray(receipt)) {
    throw new Error("The report does not contain a LatchLens receipt.");
  }

  const checks = [];
  const hashPattern = HASH_PATTERN;
  const hasReceiptShape =
    [RECEIPT_SCHEMA_V1, RECEIPT_SCHEMA_V2].includes(receipt.schema) &&
    hashPattern.test(receipt.policyHash || "") &&
    hashPattern.test(receipt.reportHash || "");
  checks.push(
    verificationCheck(
      "receipt-shape",
      "Receipt format",
      hasReceiptShape,
      hasReceiptShape
        ? "The schema and SHA-256 fields are well formed."
        : "The schema or a required SHA-256 field is invalid.",
    ),
  );

  const { reportHash: claimedReportHash, rialo: receiptRialo, ...receiptCore } =
    receipt;
  const computedReportHash = await sha256Hex(stableStringify(receiptCore));
  const receiptHashMatches =
    hashPattern.test(claimedReportHash || "") &&
    computedReportHash === claimedReportHash;
  checks.push(
    verificationCheck(
      "receipt-hash",
      "Receipt integrity",
      receiptHashMatches,
      receiptHashMatches
        ? "The receipt core reproduces the downloaded report hash."
        : "The receipt content changed after its hash was created.",
    ),
  );

  const policy = normalizePolicy(policyInput);
  const computedPolicyHash = await sha256Hex(stableStringify(policy));
  const policyMatches = computedPolicyHash === receipt.policyHash;
  checks.push(
    verificationCheck(
      "policy-hash",
      "Current policy binding",
      policyMatches,
      policyMatches
        ? "The policy currently in the editor matches this receipt."
        : "Load the exact policy used to create this report, then verify again.",
    ),
  );

  const replay = analyzePolicy(policy, { now: receipt.generatedAt });
  const expectedAnalysis = reportAnalysis(replay);
  const replayMatches = sameValue(report.analysis, expectedAnalysis);
  checks.push(
    verificationCheck(
      "engine-replay",
      "Attack-deck replay",
      replayMatches,
      replayMatches
        ? "All exported findings and test traces replay identically."
        : "The exported findings do not match a fresh run of this policy.",
    ),
  );

  const expectedSummary = {
    policyName: replay.policy.name || "Imported policy",
    score: replay.score,
    grade: replay.grade,
    passed: replay.passed,
    failed: replay.failed,
    findingCodes: replay.findings.map((item) => item.code).sort(),
  };
  const receiptSummary = {
    policyName: receipt.policyName,
    score: receipt.score,
    grade: receipt.grade,
    passed: receipt.passed,
    failed: receipt.failed,
    findingCodes: receipt.findingCodes,
  };
  const summaryMatches = sameValue(receiptSummary, expectedSummary);
  checks.push(
    verificationCheck(
      "summary",
      "Score and findings",
      summaryMatches,
      summaryMatches
        ? "The score, counts and finding codes match the replay."
        : "The receipt summary does not match the current policy replay.",
    ),
  );

  let liveEvidenceMatches = true;
  let liveDetail = "No live comparison is claimed by this local receipt.";
  if (receipt.liveVerification) {
    if (!report.liveVerification) {
      liveEvidenceMatches = false;
      liveDetail = "The receipt claims a live comparison, but its evidence is missing.";
    } else {
      const evidenceHash = await sha256Hex(
        stableStringify(report.liveVerification),
      );
      const liveSummary = {
        schema: report.liveVerification.schema,
        endpoint: report.liveVerification.endpoint,
        verifiedAt: report.liveVerification.verifiedAt,
        checked: report.liveVerification.checked,
        matched: report.liveVerification.matched,
        mismatched: report.liveVerification.mismatched,
        skipped: report.liveVerification.skipped,
        evidenceHash,
      };
      liveEvidenceMatches = sameValue(receipt.liveVerification, liveSummary);
      liveDetail = liveEvidenceMatches
        ? "The complete live comparison reproduces its evidence hash."
        : "The live comparison evidence or summary has changed.";
    }
  } else if (report.liveVerification) {
    liveEvidenceMatches = false;
    liveDetail = "Unbound live evidence was added to a local-only receipt.";
  }
  checks.push(
    verificationCheck(
      "live-evidence",
      "Live evidence claim",
      liveEvidenceMatches,
      liveDetail,
    ),
  );

  const expectedPayload = buildRialoPayload(receipt);
  const payloadMatches = sameValue(report.rialoPayload, expectedPayload);
  checks.push(
    verificationCheck(
      "rialo-payload",
      "Rialo payload",
      payloadMatches,
      payloadMatches
        ? "The prepared payload matches the receipt hashes and counts."
        : "The prepared Rialo payload does not match this receipt.",
    ),
  );

  const legacyUnanchored =
    receipt.schema === RECEIPT_SCHEMA_V1 &&
    receiptRialo?.status === "not-anchored" &&
    receiptRialo?.network === RIALO_DEVNET.name &&
    report.rialoPayload?.status === "prepared-not-submitted";
  const currentUnanchored =
    receipt.schema === RECEIPT_SCHEMA_V2 &&
    receiptRialo?.status === "not-anchored" &&
    receiptRialo?.network === RIALO_DEVNET.name &&
    receiptRialo?.rpc === RIALO_DEVNET.rpc &&
    report.rialoPayload?.status === "prepared-not-submitted";
  const embeddedAnchorIsConsistent =
    receipt.schema === RECEIPT_SCHEMA_V2 &&
    receiptRialo?.status === "anchored" &&
    anchoredEvidenceMatches(receipt, receiptRialo.evidence) &&
    receiptRialo.programId === receiptRialo.evidence.programId &&
    receiptRialo.transactionSignature ===
      receiptRialo.evidence.transactionSignature &&
    report.rialoPayload?.status === "submitted-confirmed";
  const freshAnchorEvidence = options?.rialoEvidence;
  const freshAnchorMatches =
    embeddedAnchorIsConsistent &&
    anchoredEvidenceMatches(receipt, freshAnchorEvidence) &&
    freshAnchorEvidence.programId === receiptRialo.programId &&
    freshAnchorEvidence.transactionSignature ===
      receiptRialo.transactionSignature &&
    String(freshAnchorEvidence.blockHeight) ===
      String(receiptRialo.blockHeight);
  const currentAnchored = embeddedAnchorIsConsistent && freshAnchorMatches;
  const anchorClaimIsSafe =
    legacyUnanchored || currentUnanchored || currentAnchored;
  let anchorDetail = "The file contains an unsupported or misleading anchor claim.";
  if (currentAnchored) {
    anchorDetail =
      "A fresh read from the fixed Rialo DevNet RPC confirms this program, transaction and receipt.";
  } else if (legacyUnanchored || currentUnanchored) {
    anchorDetail =
      "The file correctly says the proof has not been submitted onchain.";
  } else if (embeddedAnchorIsConsistent) {
    anchorDetail =
      options?.rialoError ||
      "Fresh public RPC confirmation is required for this anchored report.";
  }
  checks.push(
    verificationCheck(
      "anchor-claim",
      "Anchor claim",
      anchorClaimIsSafe,
      anchorDetail,
    ),
  );

  const expectedMode = receipt.liveVerification
    ? "latch-authorize-compared"
    : "local-draft";
  const modeMatches = receipt.mode === expectedMode;
  checks.push(
    verificationCheck(
      "mode",
      "Verification mode",
      modeMatches,
      modeMatches
        ? receipt.liveVerification
          ? "This is a live-compared receipt."
          : "This is a local-draft receipt."
        : "The receipt mode conflicts with its included evidence.",
    ),
  );

  return {
    valid: checks.every((check) => check.passed),
    mode: receipt.mode || "unknown",
    checks,
  };
}

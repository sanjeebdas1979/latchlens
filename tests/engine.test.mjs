import test from "node:test";
import assert from "node:assert/strict";

import {
  TEMPLATES,
  analyzePolicy,
  buildTestDeck,
  createReceipt,
  evaluateRequest,
  hardenPolicy,
  normalizePolicy,
} from "../dist/engine.js";

test("unsafe starter scores below the hardened support template", () => {
  const unsafe = analyzePolicy(TEMPLATES.unsafe.policy);
  const support = analyzePolicy(TEMPLATES.support.policy);
  assert.ok(unsafe.score < support.score);
  assert.ok(unsafe.findings.some((item) => item.code === "ENDPOINT_BLOCKLIST"));
});

test("support template denies DELETE and redacts PII", () => {
  const analysis = analyzePolicy(TEMPLATES.support.policy);
  const deletion = analysis.tests.find((item) => item.id === "destructive-delete");
  const pii = analysis.tests.find((item) => item.id === "pii-response");
  assert.equal(deletion.status, "pass");
  assert.equal(pii.status, "pass");
});

test("wildcard Rialo signer is treated as critical", () => {
  const policy = {
    name: "Wildcard signer",
    filters: [
      { type: "method", allowed: ["POST"] },
      {
        type: "endpoint",
        mode: "allowlist",
        patterns: ["/v1/transactions/sign"],
      },
      { type: "rialo_tx_signers", signers: ["*"] },
    ],
  };
  const analysis = analyzePolicy(policy);
  assert.ok(analysis.findings.some((item) => item.code === "SIGNER_WILDCARD"));
});

test("generated hardening improves an incomplete policy", () => {
  const before = analyzePolicy(TEMPLATES.unsafe.policy);
  const after = analyzePolicy(hardenPolicy(TEMPLATES.unsafe.policy));
  assert.ok(after.score > before.score);
  assert.equal(after.policy.mutability, "attenuate_only");
});

test("numeric payload rules fail closed for numeric strings", () => {
  const policy = normalizePolicy({
    filters: [
      {
        type: "payload",
        rules: [
          {
            path: "amount",
            operator: "less_than_or_equal",
            value: 10,
          },
        ],
      },
    ],
  });
  const result = evaluateRequest(policy, {
    method: "POST",
    path: "/charge",
    body: { amount: "5" },
  });
  assert.equal(result.decision, "deny");
});

test("the public attack deck stays at the advertised fourteen cases", () => {
  assert.equal(buildTestDeck(TEMPLATES.support.policy).length, 14);
});

test("receipts bind both policy and report with SHA-256 hashes", async () => {
  const receipt = await createReceipt(analyzePolicy(TEMPLATES.support.policy));
  assert.match(receipt.policyHash, /^[a-f0-9]{64}$/);
  assert.match(receipt.reportHash, /^[a-f0-9]{64}$/);
  assert.equal(receipt.rialo.status, "not-anchored");
});

import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

import { POST } from "../api/latch-authorize.js";
import {
  TEMPLATES,
  analyzePolicy,
  buildLiveVerificationPlan,
  createReceipt,
} from "../dist/engine.js";

const root = new URL("../", import.meta.url);

test("live verification sends only six safely reproducible cases", () => {
  const plan = buildLiveVerificationPlan(TEMPLATES.support.policy);

  assert.equal(plan.runnable.length, 6);
  assert.equal(plan.skipped.length, 8);
  assert.deepEqual(
    Object.keys(plan.runnable[0].request).sort(),
    ["body", "headers", "method", "path"],
  );
  assert.ok(plan.skipped.some((item) => item.id === "identity-theft"));
  assert.ok(plan.skipped.some((item) => item.id === "rate-flood"));
});

test("a live comparison is hash-bound without embedding a token", async () => {
  const liveVerification = {
    schema: "latchlens.live-verification.v1",
    endpoint: "POST /proxy/.well-known/latch-self/authorize",
    verifiedAt: "2026-10-11T00:00:00.000Z",
    checked: 6,
    matched: 6,
    mismatched: 0,
    skipped: 8,
    results: [{ id: "intended-call", decision: "allow" }],
    skippedCases: [],
  };
  const receipt = await createReceipt(
    analyzePolicy(TEMPLATES.support.policy),
    liveVerification,
  );

  assert.equal(receipt.mode, "latch-authorize-compared");
  assert.match(receipt.liveVerification.evidenceHash, /^[a-f0-9]{64}$/);
  assert.doesNotMatch(JSON.stringify(receipt), /lat_[a-z0-9]/i);
});

test("the adapter requires a Latch token and disables caching", async () => {
  const response = await POST(
    new Request("https://latchlens.test/api/latch-authorize", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ method: "GET", path: "/v1/models" }),
    }),
  );

  assert.equal(response.status, 401);
  assert.match(response.headers.get("cache-control"), /no-store/);
});

test("the adapter uses a fixed upstream and removes sensitive evidence", async () => {
  const originalFetch = globalThis.fetch;
  let captured;
  globalThis.fetch = async (url, options) => {
    captured = { url, options };
    return new Response(
      JSON.stringify({
        decision: "deny",
        requestId: "req_demo",
        latchId: "latch_private",
        deniedBy: "Method boundary",
        deniedReason: "DELETE is not allowed.",
        filterResults: [
          { filter: "method", outcome: "deny", token: "must-not-return" },
        ],
        receipt: "signed-short-lived-receipt",
      }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  };

  try {
    const response = await POST(
      new Request("https://latchlens.test/api/latch-authorize", {
        method: "POST",
        headers: {
          authorization: "Bearer lat_test_token",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          method: "DELETE",
          path: "/v1/customers/c_123",
          headers: { "x-tenant": "demo" },
          body: {},
        }),
      }),
    );
    const data = await response.json();

    assert.equal(
      captured.url,
      "https://onlatch.com/proxy/.well-known/latch-self/authorize",
    );
    assert.equal(captured.options.headers.authorization, "Bearer lat_test_token");
    assert.equal(data.decision, "deny");
    assert.equal(data.receiptIssued, true);
    assert.equal(data.filterResults[0].token, undefined);
    assert.equal(data.latchId, undefined);
    assert.equal(data.receipt, undefined);
    assert.match(response.headers.get("cache-control"), /no-store/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("the live dialog is accessible and token input is cleared", async () => {
  const [html, app] = await Promise.all([
    readFile(new URL("dist/index.html", root), "utf8"),
    readFile(new URL("dist/app.js", root), "utf8"),
  ]);

  assert.match(html, /id="liveVerifyDialog"[\s\S]*role="dialog"/);
  assert.match(html, /id="latchToken"[\s\S]*type="password"/);
  assert.match(app, /latchTokenInput\.value = ""/);
  assert.doesNotMatch(app, /localStorage\.setItem\([^\n]*(token|lat_)/i);
});

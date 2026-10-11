import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

import {
  TEMPLATES,
  analyzePolicy,
  buildAssuranceReport,
  buildRialoPayload,
  createReceipt,
  verifyAssuranceReport,
} from "../dist/engine.js";

const root = new URL("../", import.meta.url);

async function localReport(policy = TEMPLATES.support.policy) {
  const analysis = analyzePolicy(policy);
  const receipt = await createReceipt(analysis);
  return buildAssuranceReport(
    analysis,
    receipt,
    buildRialoPayload(receipt),
  );
}

test("a downloaded local report verifies against its original policy", async () => {
  const report = await localReport();
  const verification = await verifyAssuranceReport(
    report,
    TEMPLATES.support.policy,
  );

  assert.equal(verification.valid, true);
  assert.equal(verification.checks.length, 9);
  assert.ok(verification.checks.every((check) => check.passed));
});

test("receipt tampering is detected", async () => {
  const report = await localReport();
  report.receipt.score = 12;

  const verification = await verifyAssuranceReport(
    report,
    TEMPLATES.support.policy,
  );

  assert.equal(verification.valid, false);
  assert.equal(
    verification.checks.find((check) => check.id === "receipt-hash").passed,
    false,
  );
  assert.equal(
    verification.checks.find((check) => check.id === "summary").passed,
    false,
  );
});

test("a report does not verify against a different editor policy", async () => {
  const report = await localReport();
  const verification = await verifyAssuranceReport(
    report,
    TEMPLATES.unsafe.policy,
  );

  assert.equal(verification.valid, false);
  assert.equal(
    verification.checks.find((check) => check.id === "policy-hash").passed,
    false,
  );
  assert.equal(
    verification.checks.find((check) => check.id === "engine-replay").passed,
    false,
  );
});

test("changed live evidence fails its evidence hash", async () => {
  const analysis = analyzePolicy(TEMPLATES.support.policy);
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
  const receipt = await createReceipt(analysis, liveVerification);
  const report = buildAssuranceReport(
    analysis,
    receipt,
    buildRialoPayload(receipt),
    liveVerification,
  );
  report.liveVerification.results[0].decision = "deny";

  const verification = await verifyAssuranceReport(
    report,
    TEMPLATES.support.policy,
  );

  assert.equal(verification.valid, false);
  assert.equal(
    verification.checks.find((check) => check.id === "live-evidence").passed,
    false,
  );
});

test("the proof UI supports local verification without a Latch token", async () => {
  const [html, app] = await Promise.all([
    readFile(new URL("dist/index.html", root), "utf8"),
    readFile(new URL("dist/app.js", root), "utf8"),
  ]);

  assert.match(html, /id="verifyReport"/);
  assert.match(html, /id="reportFileInput"[\s\S]*accept="\.json,application\/json"/);
  assert.match(html, /id="reportVerification"[\s\S]*aria-live="polite"/);
  assert.match(html, /id="liveUseLocal"/);
  assert.match(app, /verifyAssuranceReport\(await file\.text\(\), policy\)/);
  assert.match(app, /Local proof is complete without a Latch token/);
});

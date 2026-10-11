import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { analyzePolicy } from "../dist/engine.js";

const policy = JSON.parse(
  readFileSync(
    new URL("../examples/hardened-support-policy.json", import.meta.url),
    "utf8"
  )
);

test("hardened example blocks all fourteen attacks", () => {
  const analysis = analyzePolicy(policy);

  assert.equal(analysis.tests.length, 14);
  assert.equal(analysis.passed, 14);
  assert.equal(analysis.failed, 0);
  assert.equal(analysis.counts.critical, 0);
});
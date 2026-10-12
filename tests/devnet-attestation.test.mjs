import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

import {
  GET,
  POST,
  RIALO_DEVNET_RPC,
  verifyAttestationTransaction,
} from "../api/rialo-attestation.js";
import {
  TEMPLATES,
  analyzePolicy,
  attachRialoAttestation,
  buildAssuranceReport,
  buildRialoAnchorBundle,
  buildRialoPayload,
  buildRialoVerificationRequest,
  createReceipt,
  splitHashToU64,
  verifyAssuranceReport,
} from "../dist/engine.js";

const root = new URL("../", import.meta.url);
const programId = "11111111111111111111111111111111";
const signature = "2".repeat(88);

async function fixture() {
  const analysis = analyzePolicy(TEMPLATES.support.policy);
  const receipt = await createReceipt(analysis);
  const request = buildRialoVerificationRequest(receipt, signature);
  const args = buildRialoPayload(receipt).args;
  const logs = [
    `Program ${programId} invoke [1]`,
    "Program log: latchlens:v1",
    ...Object.entries(args).map(([key, value]) => `Program log: ${key}=${value}`),
    "Program log: LatchLens assurance receipt recorded",
    `Program ${programId} success`,
  ];
  const transaction = {
    block_height: 29_300_001,
    block_time: 1_791_734_400,
    transaction: {
      signatures: [signature],
      message: {
        accountKeys: [programId],
        instructions: [{ programIdIndex: 0, accounts: [], data: "demo" }],
      },
    },
    meta: {
      err: null,
      logMessages: logs,
    },
  };
  return { analysis, receipt, request, args, transaction };
}

test("SHA-256 commitments split into four exact u64 limbs", () => {
  assert.deepEqual(splitHashToU64("f".repeat(64)), [
    "18446744073709551615",
    "18446744073709551615",
    "18446744073709551615",
    "18446744073709551615",
  ]);
  assert.throws(() => splitHashToU64("not-a-hash"), /SHA-256/);
});

test("an anchor request is deterministic receipt data with no key material", async () => {
  const { receipt } = await fixture();
  const bundle = buildRialoAnchorBundle(receipt);
  const keys = [];
  const visit = (value) => {
    if (!value || typeof value !== "object") return;
    for (const [key, child] of Object.entries(value)) {
      keys.push(key);
      visit(child);
    }
  };
  visit(bundle);

  assert.equal(bundle.schema, "latchlens.rialo-anchor-request.v1");
  assert.equal(bundle.network.rpc, RIALO_DEVNET_RPC);
  assert.equal(Object.keys(bundle.invocation.args).length, 12);
  assert.equal(bundle.safety.containsPrivateKey, false);
  assert.equal(bundle.safety.signingRequired, true);
  assert.equal(
    keys
      .filter((key) => key !== "containsPrivateKey")
      .some((key) => /seed|mnemonic|secret|private.?key|token/i.test(key)),
    false,
  );
});

test("public DevNet evidence attaches to and verifies with the exact report", async () => {
  const { analysis, receipt, request, transaction } = await fixture();
  const evidence = verifyAttestationTransaction(
    transaction,
    request,
    programId,
  );
  const anchoredReceipt = attachRialoAttestation(receipt, evidence);
  const report = buildAssuranceReport(
    analysis,
    anchoredReceipt,
    buildRialoPayload(anchoredReceipt),
  );
  const verification = await verifyAssuranceReport(
    report,
    TEMPLATES.support.policy,
    { rialoEvidence: evidence },
  );

  assert.equal(anchoredReceipt.rialo.status, "anchored");
  assert.equal(anchoredReceipt.rialo.blockHeight, "29300001");
  assert.equal(verification.valid, true);
  assert.equal(verification.checks.length, 9);
});

test("an embedded anchor claim needs a fresh public RPC confirmation", async () => {
  const { analysis, receipt, request, transaction } = await fixture();
  const evidence = verifyAttestationTransaction(
    transaction,
    request,
    programId,
  );
  const anchoredReceipt = attachRialoAttestation(receipt, evidence);
  const report = buildAssuranceReport(
    analysis,
    anchoredReceipt,
    buildRialoPayload(anchoredReceipt),
  );
  const verification = await verifyAssuranceReport(
    report,
    TEMPLATES.support.policy,
  );

  assert.equal(verification.valid, false);
  assert.equal(
    verification.checks.find((check) => check.id === "anchor-claim").passed,
    false,
  );
  assert.match(
    verification.checks.find((check) => check.id === "anchor-claim").detail,
    /Fresh public RPC confirmation/,
  );
});

test("changed DevNet logs cannot verify another receipt", async () => {
  const { request, transaction } = await fixture();
  transaction.meta.logMessages = transaction.meta.logMessages.map((line) =>
    line.startsWith("Program log: score=") ? "Program log: score=1" : line,
  );
  assert.throws(
    () => verifyAttestationTransaction(transaction, request, programId),
    /does not match score/,
  );
});

test("the API is read-only, pinned to one RPC and requires a configured program", async () => {
  const previous = process.env.RIALO_ATTESTOR_PROGRAM_ID;
  delete process.env.RIALO_ATTESTOR_PROGRAM_ID;
  try {
    const status = await GET();
    const statusData = await status.json();
    assert.equal(statusData.ready, false);
    assert.equal(statusData.rpc, RIALO_DEVNET_RPC);

    const response = await POST(
      new Request("https://latchlens.test/api/rialo-attestation", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      }),
    );
    assert.equal(response.status, 503);
    assert.match(response.headers.get("cache-control"), /no-store/);
  } finally {
    if (previous === undefined) {
      delete process.env.RIALO_ATTESTOR_PROGRAM_ID;
    } else {
      process.env.RIALO_ATTESTOR_PROGRAM_ID = previous;
    }
  }
});

test("the API verifies a confirmed transaction through the fixed DevNet RPC", async () => {
  const previousProgram = process.env.RIALO_ATTESTOR_PROGRAM_ID;
  const originalFetch = globalThis.fetch;
  const { request, transaction } = await fixture();
  let captured;
  process.env.RIALO_ATTESTOR_PROGRAM_ID = programId;
  globalThis.fetch = async (url, options) => {
    captured = { url, options };
    return Response.json({ jsonrpc: "2.0", id: 1, result: transaction });
  };

  try {
    const response = await POST(
      new Request("https://latchlens.test/api/rialo-attestation", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(request),
      }),
    );
    const data = await response.json();
    const rpcBody = JSON.parse(captured.options.body);

    assert.equal(response.status, 200);
    assert.equal(data.valid, true);
    assert.equal(data.evidence.programId, programId);
    assert.equal(captured.url, RIALO_DEVNET_RPC);
    assert.equal(rpcBody.id, 1);
    assert.equal(Number.isInteger(rpcBody.id), true);
    assert.equal(rpcBody.method, "getTransaction");
    assert.deepEqual(rpcBody.params, [{ signature }]);
    assert.equal(captured.options.redirect, "error");
    assert.equal(captured.options.cache, "no-store");
  } finally {
    globalThis.fetch = originalFetch;
    if (previousProgram === undefined) {
      delete process.env.RIALO_ATTESTOR_PROGRAM_ID;
    } else {
      process.env.RIALO_ATTESTOR_PROGRAM_ID = previousProgram;
    }
  }
});

test("the Proof tab exposes an accessible owner-signed DevNet flow", async () => {
  const [html, app, rust, artifactManifest, artifactBuild, artifactLib] =
    await Promise.all([
    readFile(new URL("dist/index.html", root), "utf8"),
    readFile(new URL("dist/app.js", root), "utf8"),
    readFile(new URL("program/src/lib.rs", root), "utf8"),
    readFile(new URL("program/artifact/Cargo.toml", root), "utf8"),
    readFile(new URL("program/artifact/build.rs", root), "utf8"),
    readFile(new URL("program/artifact/src/lib.rs", root), "utf8"),
  ]);

  assert.match(html, /id="prepareDevnetAnchor"/);
  assert.match(html, /id="devnetSignature"[\s\S]*autocomplete="off"/);
  assert.match(html, /id="devnetResult"[\s\S]*aria-live="polite"/);
  assert.match(app, /buildRialoVerificationRequest/);
  assert.match(app, /attachRialoAttestation/);
  assert.doesNotMatch(app, /seedPhrase|mnemonic|privateKey/);
  assert.match(rust, /passed\.checked_add\(failed\) != Some\(14\)/);
  assert.match(rust, /ProgramError::InvalidArgument/);
  assert.match(rust, /msg!\("latchlens:v1"\)/);
  assert.match(rust, /msg!\("generated_at=\{\}"/);
  assert.match(artifactManifest, /rialo-build-lib = "=0\.18\.1"/);
  assert.match(artifactBuild, /setup_polkavm_artifact_build/);
  assert.match(artifactBuild, /\.program_path\("\.\."\)/);
  assert.match(artifactLib, /RIALO_BUILD_ARTIFACT_FILE/);
});

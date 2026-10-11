# LatchLens

**Break your agent policy before an agent does.**

LatchLens is a local-first red-team lab for Latch policies. It turns a policy
pipeline into fourteen adversarial cases, explains the first denying filter,
proposes safer defaults, optionally compares safe cases with Latch's canonical
Authorize endpoint, exports a SHA-256 receipt shaped for Rialo, and verifies a
downloaded report locally against the policy currently in the editor.

Live prototype: https://latchlens.vercel.app/

New users can open **User guide** in the site header for a six-step walkthrough
from choosing a sample policy to exporting the local proof receipt.

Version 0.4 adds an owner-signed **Rialo DevNet anchor** path. LatchLens prepares
the exact twelve attestation values locally, never handles a signing key, and
accepts only a public transaction signature. Its read-only Vercel Function then
queries one fixed DevNet RPC, checks the configured program ID, successful
execution frame, exact hash limbs and score summary, and binds the public
evidence back into the downloadable report.

The same Proof tab can also verify a downloaded report locally with nine
checks, including its receipt hash, current-policy binding, deterministic
attack-deck replay, optional live evidence, exact Rialo payload, and an honest
anchored or `not-anchored` claim. Version 0.3.1's readability pass remains in
place for 100% browser zoom.

## Why this project

The public Rialo builder landscape already contains explorers, prediction
markets, games, bounties, agent marketplaces, DeFi automation, spending
controls, insurance, and generic agent control planes. LatchLens addresses a
different failure mode: an enforcement system can work perfectly while the
policy it enforces is broader than its owner intended.

The prototype tests for destructive methods, endpoint confusion, oversized
bodies, model escalation, token explosion, missing identity, off-hours use,
rate floods, spend bursts, PII egress, widening delegation, and wildcard
transaction signers.

## Run locally

The web app has no build step and no third-party browser dependencies.

```bash
npm test
python3 -m http.server 4173 --directory dist
```

Then open `http://localhost:4173`.

The local attack lab works with any static server. **Live Latch Verify** and
**Verify DevNet anchor** need their included Vercel Functions, so use the
deployed site or `vercel dev` when testing those optional features.

## Repository map

- `dist/` — self-contained web MVP and deterministic policy engine
- `api/` — narrow Latch adapter and read-only Rialo transaction verifier
- `tests/` — Node test suite for policy evaluation and receipts
- `program/` — fail-closed Rialo Venus 0.18.1 attestor
- `docs/DEVNET.md` — deployment, Vercel configuration and anchoring runbook
- `docs/research.md` — product gap scan and source trail

## Trust boundary

Local mode deliberately does **not** need a raw provider credential or a Latch
token. It mirrors documented filter behavior locally and marks unsupported or
stateful behavior. A receipt remains `not-anchored` until a matching confirmed
transaction is read back from Rialo DevNet.

Live mode is optional. The user supplies the `lat_` token for the latch whose
effective policy should match the JSON under review. The browser clears the
input immediately and sends the token as an authorization header to
`/api/latch-authorize`. That function forwards only to Latch's fixed
`POST /proxy/.well-known/latch-self/authorize` endpoint. Application code does
not persist, log, echo or export the token, and it never receives the protected
upstream credential.

Six request cases are compared live: intended access, destructive method,
unlisted admin route, encoded path confusion, model escalation, and output-token
explosion. Eight cases stay local because the endpoint cannot safely inject a
fake clock, identity, request history, spend state, upstream response,
delegation state, signer identity, or multi-megabyte body. The report records
each skip instead of presenting it as live proof.

The DevNet flow has a separate trust boundary. The browser downloads public
commitments, but signing and submission happen in the owner's Rialo toolchain
or wallet. The browser sends only a public transaction signature and expected
hashes to `/api/rialo-attestation`; that function cannot choose another RPC or
program ID. It returns sanitized public evidence and never accepts a seed,
private key, mnemonic, wallet file or arbitrary RPC URL.

## Verify a downloaded proof

1. Keep the same policy in the editor, or import the exact policy used to make
   the report.
2. Open **Proof** and choose **Verify downloaded report**.
3. Select `latchlens-assurance-report.json`.
4. Review the nine local checks. A valid result confirms that the receipt,
   policy, attack-deck replay, optional live evidence and prepared Rialo payload
   still agree.

The report deliberately does not embed the private policy. If the editor holds
a different policy, the verifier fails the policy-binding and replay checks
instead of making a false claim.

## Anchor on Rialo DevNet

The code path is complete, but the attestor is intentionally **not claimed as
deployed** until its owner signs a deployment and configures the returned
program ID. See [`docs/DEVNET.md`](docs/DEVNET.md) for the safe sequence.

At a high level:

1. deploy `program/` with an owner-controlled Rialo DevNet wallet;
2. add the public ID as Vercel's `RIALO_ATTESTOR_PROGRAM_ID`;
3. generate a fresh proof and download its anchor request;
4. invoke `attest_policy_report` with the twelve ordered decimal values;
5. paste the confirmed public signature into LatchLens;
6. download the report again after it says **anchored**.

Production integration should:

1. expand canonical checks as Latch exposes safe simulation inputs;
2. compare every supported trace with the local mirror;
3. split the two 32-byte hashes into four big-endian `u64` limbs each;
4. submit only the hashes and summary to the deployed Rialo attestor;
5. use a Rialo workflow and native timers to re-test on policy drift.

The DevNet verifier proves that a configured attestor emitted the matching
public values. It does not turn a local policy score into proof of live Latch
enforcement; the report continues to label local and live-compared modes.

## Security notes

- Do not paste secrets into the editor; LatchLens only needs policy JSON.
- Never paste a `lat_` token into source code, Git, Discord, or an issue.
- Never paste a wallet seed phrase, mnemonic or private key into LatchLens.
- Live verification sends the token through the deployed Vercel Function over
  HTTPS; use only a narrowly scoped token for the policy being reviewed.
- A local pass is evidence for review, not proof of live Latch behavior.
- Current Latch device identity is modeled at `self_asserted` assurance.
- A Rialo or EVM signer list containing `"*"` is treated as critical.
- Suggested hardening values are placeholders and require owner review.
- Treat `RIALO_ATTESTOR_PROGRAM_ID` as public configuration, not a secret.

## License

Prototype supplied for the Rialo builder ecosystem. Add the competition's
required license before public source distribution.

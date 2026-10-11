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

Version 0.3 adds **Verify downloaded report** under the Proof tab. It replays
the attack deck and checks the receipt hash, current-policy binding, live
evidence claim, Rialo payload, and honest `not-anchored` status without sending
the report or policy anywhere.

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

The local attack lab works with any static server. **Live Latch Verify** also
needs the included Vercel Function, so use the deployed site or `vercel dev`
when testing that optional feature.

## Repository map

- `dist/` — self-contained web MVP and deterministic policy engine
- `api/` — narrow server-side adapter for Latch Authorize
- `tests/` — Node test suite for policy evaluation and receipts
- `program/` — Rialo Venus 0.18.1 attestor scaffold
- `docs/research.md` — product gap scan and source trail

## Trust boundary

Local mode deliberately does **not** need a raw provider credential or a Latch
token. It mirrors documented filter behavior locally, marks unsupported or
stateful behavior, and labels every receipt `not-anchored`.

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

Production integration should:

1. expand canonical checks as Latch exposes safe simulation inputs;
2. compare every supported trace with the local mirror;
3. split the two 32-byte hashes into four big-endian `u64` limbs each;
4. submit only the hashes and summary to the deployed Rialo attestor;
5. use a Rialo workflow and native timers to re-test on policy drift.

The attestor is a reviewed scaffold, not a deployed program. It must be built
against the current Rialo toolchain, tested on DevNet, and wired to the live
Latch API before production use.

## Security notes

- Do not paste secrets into the editor; LatchLens only needs policy JSON.
- Never paste a `lat_` token into source code, Git, Discord, or an issue.
- Live verification sends the token through the deployed Vercel Function over
  HTTPS; use only a narrowly scoped token for the policy being reviewed.
- A local pass is evidence for review, not proof of live Latch behavior.
- Current Latch device identity is modeled at `self_asserted` assurance.
- A Rialo or EVM signer list containing `"*"` is treated as critical.
- Suggested hardening values are placeholders and require owner review.

## License

Prototype supplied for the Rialo builder ecosystem. Add the competition's
required license before public source distribution.

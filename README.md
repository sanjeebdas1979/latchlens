# LatchLens

**Break your agent policy before an agent does.**

LatchLens is a local-first red-team lab for Latch policies. It turns a policy
pipeline into fourteen adversarial cases, explains the first denying filter,
proposes safer defaults, and exports a SHA-256 receipt shaped for Rialo.

Live prototype: https://latchlens.gladshrew64.chatgpt.site

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

## Repository map

- `dist/` — self-contained web MVP and deterministic policy engine
- `tests/` — Node test suite for policy evaluation and receipts
- `program/` — Rialo Venus 0.18.1 attestor scaffold
- `docs/research.md` — product gap scan and source trail

## Trust boundary

This MVP deliberately does **not** accept a raw provider credential or a Latch
token. It mirrors documented filter behavior locally, marks unsupported or
stateful behavior, and labels every receipt `not-anchored`.

Production integration should:

1. send generated cases to Latch Simulate for canonical decisions;
2. compare those traces with the local mirror;
3. split the two 32-byte hashes into four big-endian `u64` limbs each;
4. submit only the hashes and summary to the deployed Rialo attestor;
5. use a Rialo workflow and native timers to re-test on policy drift.

The attestor is a reviewed scaffold, not a deployed program. It must be built
against the current Rialo toolchain, tested on DevNet, and wired to the live
Latch API before production use.

## Security notes

- Do not paste secrets into the editor; LatchLens only needs policy JSON.
- A local pass is evidence for review, not proof of live Latch behavior.
- Current Latch device identity is modeled at `self_asserted` assurance.
- A Rialo or EVM signer list containing `"*"` is treated as critical.
- Suggested hardening values are placeholders and require owner review.

## License

Prototype supplied for the Rialo builder ecosystem. Add the competition's
required license before public source distribution.

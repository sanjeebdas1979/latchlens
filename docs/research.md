# Research and differentiation notes

Research snapshot: 10 October 2026.

## Product thesis

Latch converts raw credentials into scoped, attenuable authority. Rialo adds
event-driven workflows, native web access, and verifiable execution. The gap is
assurance: builders need to know whether a policy's *meaning* matches its
owner's intent before an autonomous agent gets the authority.

LatchLens is therefore a policy red-team and evidence layer, not another
wallet, explorer, prediction market, or generic dashboard.

## Public builder scan

The scan covered the Rialo GitHub topic and recently indexed public projects.
Observed categories included:

- explorers and event/log viewers;
- weather and general prediction markets;
- arcade games and consumer demos;
- GitHub bounty and procurement flows;
- reactive DeFi/intent automation;
- agent marketplaces and identity;
- spending guardrails and agent control planes;
- insurance, scam checks, and uptime products.

No public project found in this scan combined policy fuzzing, first-deny trace
explanations, a hardening patch, deterministic receipts, and a Rialo anchoring
path. This is a bounded public-source finding, not a claim that no private or
unindexed implementation can exist.

## Primary sources

- Rialo Dev Portal: https://www.rialo.io/for-devs
- Rialo, “Making Agent Economy Simple and Safe”:
  https://www.rialo.io/blog/making-agent-economy-simple-and-safe
- Latch documentation: https://onlatch.com/docs
- Latch filter reference: https://onlatch.com/docs/reference/filters
- Latch simulation: https://onlatch.com/docs/guides/simulate
- Latch extension and attenuation:
  https://onlatch.com/docs/guides/extending-latches
- Rialo GitHub topic: https://github.com/topics/rialo
- Rialo Venus DSL 0.18.1: https://docs.rs/rialo-venus-dsl/0.18.1

## Production milestones

1. Map the local schema exactly to the current Latch API schema.
2. Add authenticated Latch Simulate calls through a small server-side adapter.
3. Create property-based generators from each filter's boundary values.
4. Deploy and verify `LatchLensAttestor` on Rialo DevNet.
5. Schedule drift tests with a Rialo workflow and emit alerts only on changes.
6. Add signed report verification and a public, policy-redacted proof page.

# LatchLens Rialo DevNet runbook

Status: the v0.4.0 attestor is deployed on Rialo DevNet and a full public
attestation was verified on 12 October 2026. Deployment and attestation
transactions remain owner-signed. LatchLens never receives the wallet's seed
phrase or private key.

## What the flow proves

| Stage | Owner | Evidence |
| --- | --- | --- |
| Create proof | Browser | SHA-256 policy and report commitments |
| Prepare request | Browser | Twelve ordered unsigned decimal arguments |
| Deploy / invoke | Owner wallet | Signed Rialo DevNet transaction |
| Verify | Vercel Function | Program ID, success frame, logs and block height |
| Export again | Browser | Report containing matched public evidence |

This proves that the configured `LatchLensAttestor` recorded the exact receipt
commitments. It does not claim that a local-only test was executed by Latch; the
receipt keeps `local-draft` and `latch-authorize-compared` modes distinct.

## Verified public deployment

| Field | Public value |
| --- | --- |
| Program ID | `GstS1TAvdytdzYWSauEGouaxmGRYBoiyvjqtHfjWopfp` |
| Loader | `RiscVLoader11111111111111111111111111111111` |
| Deployment slot | `29376497` |
| Attestation block | `29819199` |
| Result | `100/100` — 14 protected, 0 exposed |
| Policy SHA-256 | `794b74b578f281ddd79f958e61201c3e1a771354d5b5c1e5e649bf0abb61b073` |
| Report SHA-256 | `97a0b63a0dd84d2142700bf7edd7cb4fb786e5ebff2fe3af037d711f23439033` |

Attestation transaction signature:

```text
xeAqtY8qTwZyrHphEHKLTmGLKGvd68o5fdsA3eXFevZxz9XAnDdWrcBAXs4qYCJSHYQLp9HL1huCJ5Bw9VFAYkf
```

The production verifier freshly read this transaction from the fixed public
RPC, matched all twelve emitted values, and the downloaded anchored report
passed all nine local checks. These identifiers are public evidence; no key
material is included here.

## 1. Prepare the official toolchain

The program currently pins the published Rialo Venus packages at `0.18.1`.
Follow the current Rialo developer onboarding documentation rather than copying
an unverified deployment command from a third party:

- Dev Portal: https://www.rialo.io/for-devs
- Rialo CDK 0.18.1: https://docs.rs/rialo-cdk/0.18.1/rialo_cdk/
- Rialo Discord, linked by the Dev Portal, for DevNet access and faucets

The official toolchain installer documentation currently targets Linux and
macOS. On Windows, use WSL2 unless the current Rialo onboarding guide gives you
a native Windows path.

From the repository, make the non-signing checks first:

```bash
npm test
cd program
cargo +rialo check
```

Do not put a seed, mnemonic, private key or wallet export in this repository,
`.env`, Vercel, Discord, screenshots, or an anchor-request JSON file.

## 2. Build and deploy the attestor

The repository includes the official stable-Cargo artifact wrapper expected by
`rialo client program deploy-venus`. From `program/`, build the PolkaVM blob:

```bash
cargo build --manifest-path artifact/Cargo.toml
find target/rialo-build -type f -name '*.polkavm' -print
```

The wrapper calls the pinned `rialo-build-lib` 0.18.1 helper, which runs the
owner-installed `cargo +rialo` toolchain against the sibling program and writes
the discoverable artifact under `program/target/rialo-build/`.

Keep the payer and program-identity keys separate. The payer alias used in this
runbook is `latchlens-devnet`; create the program key once if it does not exist:

```bash
rialo keytool generate latchlens-program
```

Then deploy from `program/` to **Rialo DevNet**:

```bash
rialo -n devnet -a latchlens-devnet client program deploy-venus . \
  --keypair "$HOME/.config/rialo/latchlens-program.keypair"
```

This is an owner-signed DevNet transaction and spends only DevNet RLO. Record
the returned public program ID; never copy either keypair file into the
repository, Vercel, Discord, a report, or an anchor request.

Before continuing, confirm all of these:

- `program/src/lib.rs` built without modification to its twelve arguments;
- the target network is DevNet;
- the public program ID is 32–64 Base58 characters;
- no signing material was copied into LatchLens or Vercel.

The app's verifier is pinned to:

```text
https://devnet.rialo.io:4101
```

## 3. Pin the public program ID in Vercel

In Vercel, open **LatchLens → Settings → Environment Variables** and add:

```text
Name:  RIALO_ATTESTOR_PROGRAM_ID
Value: GstS1TAvdytdzYWSauEGouaxmGRYBoiyvjqtHfjWopfp
Environment: Production
```

Redeploy the latest `main` commit. Preview deployments need the same variable
in Preview if you want to test there. The program ID is public configuration,
not a secret.

Check the deployment:

```text
GET https://latchlens.vercel.app/api/rialo-attestation
```

It should return `"ready": true`, the fixed RPC and the public program ID. If
it says `false`, verify the variable's spelling/environment and redeploy.

## 4. Create and submit one anchor

1. Open LatchLens and run the 14-case suite on the intended policy.
2. Open **Proof** and click **Download anchor request**.
3. Inspect `latchlens-rialo-anchor-request.json`. It must say
   `containsPrivateKey: false` and `signingRequired: true`.
4. With the official owner-controlled Rialo client, invoke
   `attest_policy_report` using the twelve values in `invocation.args`, in the
   manifest's declared argument order.
5. Wait for the transaction to confirm and copy only its public signature.
6. Paste that signature into **Confirmed transaction signature** and choose
   **Verify DevNet anchor**.
7. After the UI says **anchored**, click **Download report** again. The earlier
   download is still honestly `not-anchored` and cannot update itself.

Keep the exact receipt loaded while its transaction is being signed. Every new
suite run creates a fresh `generatedAt` value and therefore a new `reportHash`.
If the page is reloaded or the suite is run again, an earlier transaction must
fail the commitment check even when the policy and score look identical. That
failure is expected binding protection; create and submit the new request.

The twelve values are four big-endian `u64` limbs for each SHA-256 hash, then
`score`, `passed`, `failed`, and the receipt generation time in Unix
milliseconds. The program rejects zero hashes, scores above 100, any attack
count other than 14, and a zero timestamp.

## 5. What the verifier checks

`api/rialo-attestation.js` accepts only a public signature plus expected public
commitments. It then checks:

1. the fixed Rialo DevNet RPC returned a confirmed transaction;
2. the submitted signature is present in that transaction;
3. the transaction succeeded (`meta.err` is null);
4. the configured program ID is a direct instruction target;
5. exactly one successful invocation frame belongs to that program;
6. the frame contains one `latchlens:v1` marker;
7. all twelve log values occur once and match the local receipt exactly;
8. the program emitted its receipt-written confirmation;
9. the RPC returned a valid block height.

Responses are `no-store`. The endpoint does not accept arbitrary RPC URLs or
program IDs, does not submit transactions, and does not need a wallet key.

## Troubleshooting

| Message | Meaning | Action |
| --- | --- | --- |
| Program deployment pending | Vercel has no valid program ID | Add the variable and redeploy |
| Transaction not confirmed | RPC returned no transaction yet | Wait briefly, then retry |
| Program was not invoked | Signature belongs to another call | Submit the downloaded request to this attestor |
| Commitment does not match | Values or report differ | Generate a fresh request and submit it exactly |
| Transaction does not match `report_hash_0` | The receipt was regenerated after submission | Keep the current receipt unchanged or submit its fresh request |
| Policy changed while verifying | Editor was changed mid-check | Run the suite again and use its new request |
| Status check unavailable | Function or network is unavailable | Check Vercel deployment/functions, then retry |

## Completion checklist

- [x] All Node tests pass.
- [x] The Venus program builds with the official current toolchain.
- [x] Owner deployed it to Rialo DevNet.
- [x] Vercel reports `ready: true` with the correct public ID.
- [x] A real transaction verifies in the Proof tab.
- [x] The newly downloaded report verifies 9/9 locally.
- [x] The public transaction signature and live demo are documented.

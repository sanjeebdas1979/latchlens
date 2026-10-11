//! Rialo-side receipt registry for LatchLens.
//!
//! The browser never handles a signing key. An owner-controlled DevNet wallet
//! can submit the twelve deterministic values in a LatchLens anchor request,
//! then the public transaction logs can be verified against the local report.

use rialo_venus_proc_macro::rialo;

rialo! {
    workflow {
        state {
            policy_hash_0: u64,
            policy_hash_1: u64,
            policy_hash_2: u64,
            policy_hash_3: u64,
            report_hash_0: u64,
            report_hash_1: u64,
            report_hash_2: u64,
            report_hash_3: u64,
            score: u64,
            passed: u64,
            failed: u64,
            generated_at: u64,
            attestation_count: u64,
        }

        program {
            use rialo_s_program::{
                entrypoint::ProgramResult,
                msg,
                program_error::ProgramError,
            };

            initiating fn attest_policy_report(
                &mut self,
                policy_hash_0: u64,
                policy_hash_1: u64,
                policy_hash_2: u64,
                policy_hash_3: u64,
                report_hash_0: u64,
                report_hash_1: u64,
                report_hash_2: u64,
                report_hash_3: u64,
                score: u64,
                passed: u64,
                failed: u64,
                generated_at: u64,
            ) -> ProgramResult {
                let empty_policy_hash = policy_hash_0 == 0
                    && policy_hash_1 == 0
                    && policy_hash_2 == 0
                    && policy_hash_3 == 0;
                let empty_report_hash = report_hash_0 == 0
                    && report_hash_1 == 0
                    && report_hash_2 == 0
                    && report_hash_3 == 0;
                let invalid_case_count = passed.checked_add(failed) != Some(14);

                if empty_policy_hash
                    || empty_report_hash
                    || score > 100
                    || invalid_case_count
                    || generated_at == 0
                {
                    msg!("LatchLens rejected invalid assurance values");
                    return Err(ProgramError::InvalidArgument);
                }

                self.policy_hash_0 = policy_hash_0;
                self.policy_hash_1 = policy_hash_1;
                self.policy_hash_2 = policy_hash_2;
                self.policy_hash_3 = policy_hash_3;
                self.report_hash_0 = report_hash_0;
                self.report_hash_1 = report_hash_1;
                self.report_hash_2 = report_hash_2;
                self.report_hash_3 = report_hash_3;
                self.score = score;
                self.passed = passed;
                self.failed = failed;
                self.generated_at = generated_at;
                self.attestation_count = self.attestation_count.saturating_add(1);

                // These exact key/value lines make a confirmed public
                // transaction independently checkable without reading secrets.
                msg!("latchlens:v1");
                msg!("policy_hash_0={}", policy_hash_0);
                msg!("policy_hash_1={}", policy_hash_1);
                msg!("policy_hash_2={}", policy_hash_2);
                msg!("policy_hash_3={}", policy_hash_3);
                msg!("report_hash_0={}", report_hash_0);
                msg!("report_hash_1={}", report_hash_1);
                msg!("report_hash_2={}", report_hash_2);
                msg!("report_hash_3={}", report_hash_3);
                msg!("score={}", score);
                msg!("passed={}", passed);
                msg!("failed={}", failed);
                msg!("generated_at={}", generated_at);
                msg!("LatchLens assurance receipt recorded");
                Ok(())
            }
        }
    }
}

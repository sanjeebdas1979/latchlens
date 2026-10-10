//! Rialo-side receipt registry for LatchLens.
//!
//! The browser never submits a transaction. A deployer can feed the eight
//! u64 hash limbs emitted by an integration client into this program after a
//! report has been confirmed against Latch Simulate.

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
            use rialo_s_program::{entrypoint::ProgramResult, msg};

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
                self.attestation_count += 1;

                msg!("LatchLens assurance receipt recorded");
                Ok(())
            }
        }
    }
}

//! Host-side handle for the owner-built LatchLens PolkaVM artifact.

/// Exact bytecode produced by the official Rialo build helper.
pub const LATCHLENS_ATTESTOR_POLKAVM: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/",
    env!("RIALO_BUILD_ARTIFACT_FILE")
));

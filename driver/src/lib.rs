//! Safe public proof projection shared by producer and independent verifier.
#[cfg(feature = "signature-link")]
pub mod signature_link;
pub mod public_coin;
pub mod public_event;
#[cfg(feature = "direct-per-key")]
pub mod per_key;
#[cfg(feature = "direct-per-key")]
pub mod per_key_probes;

#[cfg(all(feature = "two-step", feature = "direct-per-key"))]
compile_error!("two-step and direct-per-key select different SDKs and cannot be enabled together");

/// Refuse an SDK/profile mismatch before any RPC or native wallet operation.
pub fn validate_architecture(requested: Option<&str>) -> anyhow::Result<()> {
    let expected = if cfg!(feature = "signature-link") {
        "signature_link"
    } else if cfg!(feature = "two-step") {
        "two_step_per_key"
    } else if cfg!(feature = "direct-per-key") {
        "direct_per_key"
    } else {
        "direct_xpub"
    };
    let historical_direct = !cfg!(any(feature = "two-step", feature = "direct-per-key", feature = "signature-link"))
        && requested.is_none();
    anyhow::ensure!(requested == Some(expected) || historical_direct,
        "compiled native adapter requires architecture profile {expected}");
    Ok(())
}

#[cfg(all(feature = "signature-link", any(feature = "two-step", feature = "direct-per-key")))]
compile_error!("signature-link must be built separately from legacy SDK adapters");

//! Safe public proof projection shared by producer and independent verifier.
pub mod public_coin;
pub mod public_event;
#[cfg(feature = "direct-per-key")]
pub mod per_key;

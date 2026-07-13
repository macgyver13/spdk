//! MuSig2 silent-payment support for BIP-375 PSBTs.
//!
//! The standard SP signer handles one ECDH share per eligible input. A MuSig2
//! input instead needs participant shares to be verified and combined with the
//! BIP-327 coefficients before the ordinary BIP-352 output calculation. The
//! signer role itself lives in [`crate::roles::musig2_signer`].

mod constructor;

pub mod finalizer;
pub mod keyagg;
pub mod shares;

pub use constructor::build_psbt;
pub use finalizer::finalize_sp_outputs;

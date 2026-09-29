//! BIP-375 extensions for `psbt-v2` PSBTs.
//!
//! - [`signer`]: ECDH shares and silent-payment output derivation.
//! - [`extractor`]: output-script check before extraction.
//!
//! `Psbt` and the upstream signer, finalizer, and extractor types are in `psbt-v2`.
//!
//! A combiner for concurrent signers is not implemented. It would merge ECDH shares, DLEQ
//! proofs, and signatures, and reject conflicting values for the same field.

pub mod extractor;
pub mod musig2;
pub mod musig2_signer;
pub mod signer;

use psbt_v2::bitcoin::TxOut;
use psbt_v2::{FundingUtxoError, Input};

/// Returns the output `input` spends, accepting a witness-only UTXO for any script type.
///
/// `Input::funding_utxo_untrusted` rejects a witness-only non-P2TR input because its amount
/// cannot be checked against a full transaction. Silent payment PSBTs routinely carry such
/// inputs, and this crate reads the funding output only to classify the script and to derive
/// shared secrets, not to vouch for the amount, so that one case is waived. Every structural
/// error is still reported.
pub(crate) fn funding_utxo(input: &Input) -> Result<&TxOut, FundingUtxoError> {
    match input.funding_utxo_untrusted() {
        Err(FundingUtxoError::UnverifiableUtxo) => input
            .witness_utxo
            .as_ref()
            .ok_or(FundingUtxoError::MissingUtxo),
        result => result,
    }
}

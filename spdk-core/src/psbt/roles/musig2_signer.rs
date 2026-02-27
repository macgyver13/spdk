//! MuSig2 Signer Role (BIP-327 + BIP-373)
//!
//! Implements MuSig2 N-of-N collaborative signing for PSBT inputs, using
//! BIP-373 PSBT fields for participant key exchange, nonce exchange, and
//! partial signature exchange.
//!
//! # Byte Boundary Note
//!
//! This module uses the `musig2` crate which depends on `secp256k1 = "0.31"`,
//! while the rest of the workspace uses `secp256k1 = "0.29"`. The types are
//! incompatible at the Rust level, so all key material crosses the version
//! boundary via serialized bytes. This is isolated to the conversion helpers
//! at the bottom of this module and will be removed once the workspace
//! upgrades to secp256k1 0.31+.

use crate::psbt::core::{Bip375PsbtExt, Error, Result, SilentPaymentPsbt};
use musig2::{
    aggregate_partial_signatures, sign_partial, AggNonce, BinaryEncoding, CompactSignature,
    KeyAggContext, PartialSignature, PubNonce, SecNonce,
};
use secp256k1::{PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};

// ===== Key Aggregation =====

/// Aggregate participant public keys into a MuSig2 key aggregation context.
///
/// Returns the `KeyAggContext` (needed for nonce generation and signing) and
/// the tweaked aggregate x-only public key (the P2TR internal key to use).
///
/// # Arguments
/// * `participants` - Ordered list of participant public keys (secp256k1 0.29)
pub fn aggregate_musig2_keys(
    participants: &[PublicKey],
) -> Result<(KeyAggContext, XOnlyPublicKey)> {
    let key_agg_ctx = crate::psbt::crypto::musig2::build_key_agg_ctx(participants)?;

    let agg_xonly: musig2::secp256k1::XOnlyPublicKey = key_agg_ctx.aggregated_pubkey();
    let xonly = crate::psbt::crypto::musig2::from_musig2_xonly(&agg_xonly)?;

    Ok((key_agg_ctx, xonly))
}

// ===== Nonce Generation =====

/// Generate a MuSig2 nonce for one participant and write it to the PSBT.
///
/// Returns the `SecNonce` — the caller MUST keep this secret and use it
/// exactly once in `add_musig2_partial_sig`. Never serialize or store it.
///
/// # Arguments
/// * `psbt` - The PSBT to write the nonce into
/// * `input_index` - Index of the MuSig2 input
/// * `participant_sk` - This participant's secret key
/// * `participant_pk` - This participant's public key
/// * `agg_pk` - The aggregate public key (from `aggregate_musig2_keys`)
/// * `key_agg_ctx` - The key aggregation context
/// * `nonce_seed` - 32-byte random seed (must be unique per signing session)
pub fn add_musig2_pub_nonce(
    psbt: &mut SilentPaymentPsbt,
    input_index: usize,
    participant_sk: &SecretKey,
    participant_pk: &PublicKey,
    agg_pk: &PublicKey,
    key_agg_ctx: &KeyAggContext,
    nonce_seed: [u8; 32],
) -> Result<SecNonce> {
    let musig2_seckey = sk_029_to_musig2_scalar(participant_sk)?;
    let musig2_agg_pk: musig2::secp::Point = pk_029_to_musig2_point(agg_pk)?;

    let sec_nonce = SecNonce::build(nonce_seed)
        .with_seckey(musig2_seckey)
        .with_aggregated_pubkey(musig2_agg_pk)
        .build();

    let pub_nonce: PubNonce = sec_nonce.public_nonce();
    let nonce_arr: [u8; 66] = BinaryEncoding::to_bytes(&pub_nonce);

    psbt.add_input_musig2_pub_nonce(input_index, participant_pk, agg_pk, nonce_arr)?;

    // Advance key_agg_ctx not needed — just pass the sec_nonce back
    let _ = key_agg_ctx; // used above for context; kept as param for API consistency

    Ok(sec_nonce)
}

// ===== Partial Signing =====

/// Produce a MuSig2 partial signature and write it to the PSBT.
///
/// Must be called after ALL participants' nonces are in the PSBT.
/// The `sec_nonce` is consumed — it cannot be reused.
///
/// # Arguments
/// * `psbt` - The PSBT containing all nonces
/// * `input_index` - Index of the MuSig2 input
/// * `participant_sk` - This participant's secret key
/// * `participant_pk` - This participant's public key
/// * `agg_pk` - The aggregate public key
/// * `sec_nonce` - The SecNonce returned by `add_musig2_pub_nonce` (consumed)
/// * `key_agg_ctx` - The key aggregation context
/// * `message` - The sighash message to sign (32 bytes)
pub fn add_musig2_partial_sig(
    psbt: &mut SilentPaymentPsbt,
    input_index: usize,
    participant_sk: &SecretKey,
    participant_pk: &PublicKey,
    agg_pk: &PublicKey,
    sec_nonce: SecNonce,
    key_agg_ctx: &KeyAggContext,
    message: &[u8; 32],
) -> Result<()> {
    // Aggregate all nonces in the PSBT for this input
    let agg_nonce = collect_agg_nonce(psbt, input_index)?;

    let musig2_seckey = sk_029_to_musig2_scalar(participant_sk)?;

    let partial_sig: PartialSignature = sign_partial(
        key_agg_ctx,
        musig2_seckey,
        sec_nonce,
        &agg_nonce,
        message.as_slice(),
    )
    .map_err(|e| Error::Musig2(format!("partial signing failed: {e}")))?;

    // PartialSignature is a MaybeScalar — serialize to 32 bytes
    let sig_bytes: [u8; 32] = partial_sig.serialize();

    psbt.add_input_musig2_partial_sig(input_index, participant_pk, agg_pk, sig_bytes)?;

    Ok(())
}

// ===== Signature Aggregation =====

/// Aggregate all MuSig2 partial signatures and write the final Schnorr signature
/// to `tap_key_sig` on the input.
///
/// Must be called after ALL participants' partial signatures are in the PSBT.
///
/// # Arguments
/// * `psbt` - The PSBT containing all partial signatures
/// * `input_index` - Index of the MuSig2 input
/// * `key_agg_ctx` - The key aggregation context
/// * `message` - The sighash message that was signed (32 bytes)
/// * `secp` - The secp256k1 context (for finalizing tap_key_sig)
pub fn aggregate_musig2_sigs(
    psbt: &mut SilentPaymentPsbt,
    input_index: usize,
    key_agg_ctx: &KeyAggContext,
    message: &[u8; 32],
    secp: &Secp256k1<secp256k1::All>,
) -> Result<()> {
    let agg_nonce = collect_agg_nonce(psbt, input_index)?;

    let partial_sigs_raw = psbt.get_input_musig2_partial_sigs(input_index);
    if partial_sigs_raw.is_empty() {
        return Err(Error::MissingMusig2PartialSigs(input_index));
    }

    let partial_sigs: Vec<PartialSignature> = partial_sigs_raw
        .iter()
        .map(|(_, _, sig_bytes)| {
            PartialSignature::from_slice(sig_bytes.as_slice())
                .map_err(|e| Error::Musig2(format!("invalid partial sig: {e}")))
        })
        .collect::<Result<_>>()?;

    let final_sig: CompactSignature =
        aggregate_partial_signatures(key_agg_ctx, &agg_nonce, partial_sigs, message.as_slice())
            .map_err(|e| Error::Musig2(format!("signature aggregation failed: {e}")))?;

    // Convert musig2 CompactSignature -> secp256k1 schnorr::Signature via bytes
    let musig2_031_sig: musig2::secp256k1::schnorr::Signature = final_sig.into();
    let sig_bytes = musig2_031_sig.to_byte_array();
    let schnorr_sig =
        secp256k1::schnorr::Signature::from_slice(&sig_bytes).map_err(|e| Error::Secp256k1(e))?;

    let tap_sig = bitcoin::taproot::Signature {
        signature: schnorr_sig,
        sighash_type: bitcoin::sighash::TapSighashType::Default,
    };

    let input = psbt
        .inputs
        .get_mut(input_index)
        .ok_or(Error::InvalidInputIndex(input_index))?;
    input.tap_key_sig = Some(tap_sig);

    let _ = secp; // available for future use (e.g., signature verification)

    Ok(())
}

// ===== Internal Helpers =====

/// Collect all public nonces from the PSBT and aggregate them into an AggNonce.
fn collect_agg_nonce(psbt: &SilentPaymentPsbt, input_index: usize) -> Result<AggNonce> {
    let nonces_raw = psbt.get_input_musig2_pub_nonces(input_index);
    if nonces_raw.is_empty() {
        return Err(Error::MissingMusig2Nonces(input_index));
    }

    let pub_nonces: Vec<PubNonce> = nonces_raw
        .iter()
        .map(|(_, _, nonce_bytes)| {
            PubNonce::from_bytes(nonce_bytes.as_slice())
                .map_err(|e| Error::Musig2(format!("invalid pub nonce: {e}")))
        })
        .collect::<Result<_>>()?;

    Ok(AggNonce::sum(pub_nonces))
}

// ===== Byte-Boundary Conversion Helpers =====
// These convert between secp256k1 0.29 types (used by the workspace) and
// secp256k1 0.31 types (used by the musig2 crate) via serialized bytes.
// TODO: Remove these shims once the workspace upgrades to secp256k1 0.31+.

fn pk_029_to_musig2_point(pk: &PublicKey) -> Result<musig2::secp::Point> {
    let bytes = pk.serialize();
    musig2::secp::Point::from_slice(&bytes)
        .map_err(|e| Error::Musig2(format!("pubkey conversion failed: {e}")))
}

fn sk_029_to_musig2_scalar(sk: &SecretKey) -> Result<musig2::secp::Scalar> {
    let bytes = sk.secret_bytes();
    musig2::secp::Scalar::from_slice(&bytes)
        .map_err(|e| Error::Musig2(format!("seckey conversion failed: {e}")))
}

//! MuSig2-aware silent-payment output finalization.
//!
//! The MuSig2 ECDH share is a BIP-327 weighted aggregate of participant shares
//! (see [`super::shares::aggregate_ecdh_shares`]). Once aggregated it is an
//! ordinary `secp256k1::PublicKey`, so the BIP-352 output derivation reuses the
//! same `silentpayments` public API as the single-signer path in
//! [`crate::signer`]: [`TransactionSharedSecret::new_from_aggregate_share`]
//! applies the `input_hash`, and [`generate_recipient_pubkeys`] applies the
//! per-output `BIP0352/SharedSecret` tweak.

use anyhow::{anyhow, Result};
use bitcoin::key::TweakedPublicKey;
use bitcoin::ScriptBuf;
use secp256k1::{PublicKey, Secp256k1};
use silentpayments::sending::generate_recipient_pubkeys;
use silentpayments::utils::OutPoint;
use silentpayments::{SilentPaymentKeyMaterial, SpVersion, TransactionInputs, TransactionSharedSecret};
use std::collections::HashMap;

use super::shares::aggregate_ecdh_shares;
use crate::signer::extract_eligible_input_pubkey;
use psbt_v2::Psbt;

/// Verify and aggregate MuSig2 ECDH contributions, then derive every SP output
/// script: set it when still unresolved, or check it when the signers already
/// resolved it.
///
/// The Finalizer clears the MuSig2 partial shares, so this is the only point
/// where a MuSig2 PSBT's SP outputs can be verified; call it before finalizing.
pub fn finalize_sp_outputs(secp: &Secp256k1<secp256k1::All>, psbt: &mut Psbt) -> Result<()> {
    let aggregated = aggregate_ecdh_shares(psbt, secp)?;

    // Build the eligible-input set once; the shared-secret constructor uses it to
    // compute `input_hash = hash_BIP0352/Inputs(min_outpoint || A_sum)`.
    let mut transaction_inputs = TransactionInputs::with_capacity(psbt.inputs.len());
    for input in psbt.inputs.iter() {
        let outpoint =
            OutPoint::from_txid_and_vout(&input.previous_txid.to_string(), input.spent_output_index)
                .map_err(|e| anyhow!("build outpoint: {e}"))?;
        let spk = &crate::funding_utxo(input)
            .map_err(|e| anyhow!("funding utxo: {e}"))?
            .script_pubkey;
        let pubkey = extract_eligible_input_pubkey(input).map_err(|e| anyhow!("input pubkey: {e}"))?;
        transaction_inputs.push(outpoint, spk.to_bytes(), pubkey);
    }

    let mut shared_secrets: HashMap<PublicKey, TransactionSharedSecret> =
        HashMap::with_capacity(aggregated.len());
    for (scan_key, aggregate_share) in aggregated {
        let shared_secret = TransactionSharedSecret::new_from_aggregate_share(
            secp,
            aggregate_share,
            scan_key,
            &transaction_inputs,
        )
        .map_err(|e| anyhow!("build shared secret: {e}"))?;
        shared_secrets.insert(scan_key, shared_secret);
    }

    // Collect recipient addresses in output order so `generate_recipient_pubkeys`
    // assigns the per-scan-key output counter `n` the same way it is consumed below.
    let mut recipients: Vec<SilentPaymentKeyMaterial> = Vec::new();
    for output in psbt.outputs.iter() {
        if let Some((scan_key, spend_key)) = output.sp_info() {
            recipients.push(SilentPaymentKeyMaterial::new(SpVersion::ZERO, scan_key, spend_key));
        }
    }

    let mut output_keys = generate_recipient_pubkeys(secp, recipients, &shared_secrets)
        .map_err(|e| anyhow!("generate recipient pubkeys: {e}"))?;

    for output_idx in 0..psbt.outputs.len() {
        let Some((scan_key, spend_key)) = psbt.outputs[output_idx].sp_info() else {
            continue;
        };
        let key_material = SilentPaymentKeyMaterial::new(SpVersion::ZERO, scan_key, spend_key);
        let xonly = output_keys
            .get_mut(&key_material)
            .filter(|keys| !keys.is_empty())
            .map(|keys| keys.remove(0))
            .ok_or_else(|| anyhow!("no derived output key for output {output_idx}"))?;
        let derived = ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(xonly));
        let output = &mut psbt.outputs[output_idx];
        if output.script_pubkey.is_empty() {
            output.script_pubkey = derived;
        } else if output.script_pubkey != derived {
            // The signers committed to this script, so a mismatch means they and
            // this finalizer disagree on the output; broadcasting would pay a
            // script the recipient may never find.
            return Err(anyhow!(
                "output {output_idx} script does not match the one derived from the ECDH shares"
            ));
        }
    }

    psbt.global.tx_modifiable_flags = 0;
    Ok(())
}

//! MuSig2-aware silent-payment output finalization.
//!
//! The MuSig2 ECDH share is a BIP-327 weighted aggregate of participant shares
//! (see [`super::shares::aggregate_ecdh_shares`]). Once aggregated it is an
//! ordinary `secp256k1::PublicKey`, so the BIP-352 output derivation reuses the
//! same `silentpayments` public API as the single-signer path in
//! [`crate::roles::signer`]: [`TransactionSharedSecret::new_from_aggregate_share`]
//! applies the `input_hash`, and [`generate_recipient_pubkeys`] applies the
//! per-output `BIP0352/SharedSecret` tweak.

use anyhow::{anyhow, Result};
use bitcoin::key::TweakedPublicKey;
use bitcoin::ScriptBuf;
use secp256k1::{PublicKey, Secp256k1};
use silentpayments::sending::generate_recipient_pubkeys;
use silentpayments::utils::OutPoint;
use silentpayments::{TransactionInputs, TransactionSharedSecret, SILENT_PAYMENT_ADDRESS_BYTE_LEN};
use std::collections::HashMap;

use super::shares::aggregate_ecdh_shares;
use crate::roles::signer::extract_eligible_input_pubkey;
use crate::Psbt;

/// Verify and aggregate MuSig2 ECDH contributions, then set every SP output.
pub fn finalize_sp_outputs(secp: &Secp256k1<secp256k1::All>, psbt: &mut Psbt) -> Result<()> {
    let aggregated = aggregate_ecdh_shares(psbt, secp)?;

    // Build the eligible-input set once; the shared-secret constructor uses it to
    // compute `input_hash = hash_BIP0352/Inputs(min_outpoint || A_sum)`.
    let mut transaction_inputs = TransactionInputs::with_capacity(psbt.inputs.len());
    for input in psbt.inputs.iter() {
        let outpoint =
            OutPoint::from_txid_and_vout(input.previous_txid.to_string(), input.spent_output_index)
                .map_err(|e| anyhow!("build outpoint: {e}"))?;
        let spk = &input
            .funding_utxo()
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
    let mut recipients: Vec<[u8; SILENT_PAYMENT_ADDRESS_BYTE_LEN]> = Vec::new();
    for output in psbt.outputs.iter() {
        if let Some((scan_key, spend_key)) = output.sp_info()? {
            let mut address = [0u8; SILENT_PAYMENT_ADDRESS_BYTE_LEN];
            address[1..34].copy_from_slice(&scan_key.serialize());
            address[34..].copy_from_slice(&spend_key.serialize());
            recipients.push(address);
        }
    }

    let mut output_keys = generate_recipient_pubkeys(secp, &recipients, &shared_secrets)
        .map_err(|e| anyhow!("generate recipient pubkeys: {e}"))?;

    for output_idx in 0..psbt.outputs.len() {
        let Some((scan_key, spend_key)) = psbt.outputs[output_idx].sp_info()? else {
            continue;
        };
        let mut address = [0u8; SILENT_PAYMENT_ADDRESS_BYTE_LEN];
        address[1..34].copy_from_slice(&scan_key.serialize());
        address[34..].copy_from_slice(&spend_key.serialize());
        let xonly = output_keys
            .get_mut(&address)
            .filter(|keys| !keys.is_empty())
            .map(|keys| keys.remove(0))
            .ok_or_else(|| anyhow!("no derived output key for output {output_idx}"))?;
        psbt.outputs[output_idx].script_pubkey =
            ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(xonly));
    }

    psbt.global.tx_modifiable_flags = 0;
    Ok(())
}

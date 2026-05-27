//! BIP-375 Extension Traits and PSBT Accessors
//!
//! This module provides extension traits that add BIP-375 silent payment functionality
//! to the `psbt_v2::v2::Psbt` type, along with convenience accessor functions for
//! common PSBT field access patterns.
//!
//! # Module Contents
//!
//! - **`Bip375PsbtExt` trait**: Adds BIP-375 specific methods to PSBT
//!   - ECDH share management (global and per-input)
//!   - DLEQ proof handling
//!   - Silent payment address/label fields
//!   - SP tweak fields for spending
//!
//! - **Convenience Accessors**: Higher-level functions for extracting typed data
//!   - Input field extraction (txid, vout, outpoint, pubkeys)
//!   - Output field extraction (SP keys)
//!   - Fallback logic for public key detection
//!
//! # Design Philosophy
//!
//! - **Non-invasive**: Uses extension traits rather than wrapping types
//! - **Idiomatic**: Follows rust-psbt patterns and conventions
//! - **Upstreamable**: Clean API that could be contributed to rust-psbt
//! - **Type-safe**: Leverages Rust's type system for correctness

use super::{
    error::{Error, Result},
    types::EcdhShareData,
    SilentPaymentPsbt,
};
use crate::psbt::crypto::bip352::is_input_eligible;
use bitcoin::{OutPoint, Txid};
use psbt_v2::{
    bitcoin::CompressedPublicKey,
    raw::Key,
    v2::{dleq::DleqProof, Psbt},
};
use silentpayments::secp256k1::PublicKey;
use silentpayments::SilentPaymentAddress;

pub const PSBT_OUT_DNSSEC_PROOF: u64 = 0x35;
// Proposed BIP-376 extension fields for silent payment spend key derivation
pub const PSBT_IN_SP_SPEND_BIP32_DERIVATION: u64 = 0x1f;
pub const PSBT_IN_SP_TWEAK: u64 = 0x20;

// Proposed BIP-375 extension: partial ECDH shares for MuSig2/FROST
// These are proposed new fields not yet in the BIP-375 spec.
// Key: scan_key (33B) || contributor_pubkey (33B) = 66 bytes
// Value for PARTIAL_ECDH_SHARE: partial share point (33B)
// Value for PARTIAL_DLEQ: DLEQ proof (64B)
pub const PSBT_IN_MUSIG2_PARTIAL_ECDH_SHARE: u64 = 0x21;
pub const PSBT_IN_MUSIG2_PARTIAL_DLEQ: u64 = 0x22;

/// Partial ECDH share contributed by one MuSig2/FROST participant.
///
/// Each participant computes `partial_share = sk_i * scan_key` and provides a DLEQ proof
/// proving `log_G(P_i) = log_{scan_key}(partial_share)`. The coordinator sums all partial
/// shares to obtain the aggregate ECDH share `= agg_sk * scan_key`.
///
/// This implements the proposed BIP-375 extension for threshold/multisig ECDH.
pub struct PartialEcdhShareData {
    /// The scan key this partial share is for
    pub scan_key: PublicKey,
    /// The contributor's public key (P_i = sk_i * G)
    pub contributor_pk: PublicKey,
    /// The partial ECDH share (sk_i * scan_key)
    pub share: PublicKey,
    /// DLEQ proof: proves log_G(contributor_pk) = log_{scan_key}(share). Mandatory.
    pub dleq_proof: DleqProof,
}

/// Extension trait for BIP-375 silent payment fields on PSBT v2
///
/// This trait adds methods to access and modify BIP-375 specific fields:
/// - ECDH shares (global and per-input)
/// - DLEQ proofs (global and per-input)
/// - Silent payment addresses (per-output)
/// - Silent payment labels (per-output)
pub trait Bip375PsbtExt {
    // ===== Global ECDH Shares =====

    /// Get all global ECDH shares
    ///
    /// Global shares are used when one party knows all input private keys.
    /// Field type: PSBT_GLOBAL_SP_ECDH_SHARE (0x07)
    fn get_global_ecdh_shares(&self) -> Vec<EcdhShareData>;

    /// Add a global ECDH share
    ///
    /// # Arguments
    /// * `share` - The ECDH share to add
    fn add_global_ecdh_share(&mut self, share: &EcdhShareData) -> Result<()>;

    // ===== Per-Input ECDH Shares =====

    /// Get ECDH shares for a specific input
    ///
    /// Returns per-input shares if present, otherwise falls back to global shares.
    /// Field type: PSBT_IN_SP_ECDH_SHARE (0x1d)
    ///
    /// # Arguments
    /// * `input_index` - Index of the input
    fn get_input_ecdh_shares(&self, input_index: usize) -> Vec<EcdhShareData>;

    /// Add an ECDH share to a specific input
    ///
    /// # Arguments
    /// * `input_index` - Index of the input
    /// * `share` - The ECDH share to add
    fn add_input_ecdh_share(&mut self, input_index: usize, share: &EcdhShareData) -> Result<()>;

    // ===== Silent Payment Outputs =====

    /// Get silent payment scan and spend keys for an output
    ///
    /// Field type: PSBT_OUT_SP_V0_INFO (0x09)
    ///
    /// # Arguments
    /// * `output_index` - Index of the output
    fn get_output_sp_info(&self, output_index: usize) -> Option<(PublicKey, PublicKey)>;

    /// Set silent payment v0 keys for an output
    ///
    /// # Arguments
    /// * `output_index` - Index of the output
    /// * `address` - The silent payment address
    fn set_output_sp_info(
        &mut self,
        output_index: usize,
        address: &SilentPaymentAddress,
    ) -> Result<()>;

    /// Get silent payment label for an output
    ///
    /// Field type: PSBT_OUT_SP_V0_LABEL (0x0a)
    ///
    /// **Important:** This field is metadata only. When present, the spend key in
    /// PSBT_OUT_SP_V0_INFO is already labeled. The label value is not used for
    /// cryptographic derivation during finalization.
    ///
    /// # Arguments
    /// * `output_index` - Index of the output
    fn get_output_sp_label(&self, output_index: usize) -> Option<u32>;

    /// Set silent payment label for an output
    ///
    /// **Important:** When setting this field, ensure that the spend key in
    /// PSBT_OUT_SP_V0_INFO is already labeled. This field is metadata only.
    ///
    /// # Arguments
    /// * `output_index` - Index of the output
    /// * `label` - The label value (0 = change, 1+ = labeled receiving addresses)
    fn set_output_sp_label(&mut self, output_index: usize, label: u32) -> Result<()>;

    // ===== Silent Payment Spend Key Derivation (BIP-376) =====

    /// Get silent payment tweak for an input
    ///
    /// Returns the 32-byte tweak that should be added to the spend private key
    /// to spend this silent payment output.
    ///
    /// Field type: PSBT_IN_SP_TWEAK
    ///
    /// # Arguments
    /// * `input_index` - Index of the input
    fn get_input_sp_tweak(&self, input_index: usize) -> Option<[u8; 32]>;

    /// Set silent payment tweak for an input
    ///
    /// The tweak is derived from BIP-352 output derivation during wallet scanning.
    /// Hardware signer uses this to compute: tweaked_privkey = spend_privkey + tweak
    ///
    /// Field type: PSBT_IN_SP_TWEAK
    ///
    /// # Arguments
    /// * `input_index` - Index of the input
    /// * `tweak` - The 32-byte tweak
    fn set_input_sp_tweak(&mut self, input_index: usize, tweak: [u8; 32]) -> Result<()>;

    /// Remove silent payment tweak from an input
    ///
    /// This is typically called after transaction extraction to clean up the PSBT.
    /// Prevents accidental re-use of tweaks and keeps PSBTs cleaner.
    ///
    /// Field type: PSBT_IN_SP_TWEAK
    ///
    /// # Arguments
    /// * `input_index` - Index of the input
    fn remove_input_sp_tweak(&mut self, input_index: usize) -> Result<()>;

    /// Get silent payment spend key BIP32 derivation for an input
    ///
    /// Returns the 33-byte spend public key and its BIP32 derivation path.
    /// This is used by hardware wallets to identify inputs they control when
    /// spending Silent Payment outputs.
    ///
    /// Field type: PSBT_IN_SP_SPEND_BIP32_DERIVATION
    ///
    /// # Arguments
    /// * `input_index` - Index of the input
    ///
    /// # Returns
    /// * `Some((spend_pubkey, fingerprint, path))` - The spend key and derivation info
    /// * `None` - If the field is not present
    fn get_input_sp_spend_bip32_derivation(
        &self,
        input_index: usize,
    ) -> Option<(PublicKey, [u8; 4], Vec<u32>)>;

    /// Set silent payment spend key BIP32 derivation for an input
    ///
    /// Used by the UPDATER role when spending Silent Payment outputs.
    /// The spend key is the 33-byte compressed public key that, when tweaked
    /// with PSBT_IN_SP_TWEAK, produces the key locking the output.
    ///
    /// Field type: PSBT_IN_SP_SPEND_BIP32_DERIVATION
    ///
    /// # Arguments
    /// * `input_index` - Index of the input
    /// * `spend_pubkey` - The 33-byte spend public key
    /// * `fingerprint` - Master key fingerprint (4 bytes)
    /// * `path` - BIP32 derivation path (e.g., [352', 0', 0', 1, index])
    fn set_input_sp_spend_bip32_derivation(
        &mut self,
        input_index: usize,
        spend_pubkey: &PublicKey,
        fingerprint: [u8; 4],
        path: Vec<u32>,
    ) -> Result<()>;

    /// Remove silent payment spend key BIP32 derivation from an input
    ///
    /// This is typically called after transaction extraction to clean up the PSBT.
    /// Prevents accidental re-use of tweaks and keeps PSBTs cleaner.
    ///
    /// Field type: PSBT_IN_SP_SPEND_BIP32_DERIVATION
    ///
    /// # Arguments
    /// * `input_index` - Index of the input
    fn remove_input_sp_spend_bip32_derivation(&mut self, input_index: usize) -> Result<()>;

    // ===== Convenience Methods =====

    /// Get the number of inputs
    fn num_inputs(&self) -> usize;

    /// Get the number of outputs
    fn num_outputs(&self) -> usize;

    /// Get partial signatures for an input
    ///
    /// # Arguments
    /// * `input_index` - Index of the input
    fn get_input_partial_sigs(&self, input_index: usize) -> Vec<(Vec<u8>, Vec<u8>)>;

    /// Get all scan keys from outputs with PSBT_OUT_SP_V0_INFO set
    ///
    /// Iterates through all outputs and extracts scan keys from silent payment addresses.
    /// This is used by signers to determine which scan keys need ECDH shares.
    fn get_output_scan_keys(&self) -> Vec<PublicKey>;

    // ===== BIP-373 MuSig2 Fields =====

    /// Get MuSig2 participant pubkeys for an input
    ///
    /// Returns list of (aggregate_pk, participant_pks) tuples.
    /// Field type: PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS (0x1a)
    fn get_input_musig2_participant_pubkeys(
        &self,
        input_index: usize,
    ) -> Vec<(PublicKey, Vec<PublicKey>)>;

    /// Set MuSig2 participant pubkeys for an input
    ///
    /// Field type: PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS (0x1a)
    /// Key: aggregate_pk (33B). Value: participant pubkeys concatenated (N*33B).
    fn set_input_musig2_participant_pubkeys(
        &mut self,
        input_index: usize,
        agg_pk: &PublicKey,
        participants: &[PublicKey],
    ) -> Result<()>;

    /// Get MuSig2 participant pubkeys for an output
    ///
    /// Returns list of (aggregate_pk, participant_pks) tuples.
    /// Field type: PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS (0x1d)
    fn get_output_musig2_participant_pubkeys(
        &self,
        output_index: usize,
    ) -> Vec<(PublicKey, Vec<PublicKey>)>;

    /// Set MuSig2 participant pubkeys for an output
    ///
    /// Field type: PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS (0x1d)
    /// Key: aggregate_pk (33B). Value: participant pubkeys concatenated (N*33B).
    fn set_output_musig2_participant_pubkeys(
        &mut self,
        output_index: usize,
        agg_pk: &PublicKey,
        participants: &[PublicKey],
    ) -> Result<()>;

    /// Get MuSig2 public nonces for an input
    ///
    /// Returns list of (participant_pk, aggregate_pk, nonce_bytes) tuples.
    /// Field type: PSBT_IN_MUSIG2_PUB_NONCE (0x1b)
    fn get_input_musig2_pub_nonces(
        &self,
        input_index: usize,
    ) -> Vec<(PublicKey, PublicKey, [u8; 66])>;

    /// Add a MuSig2 public nonce for an input
    ///
    /// Field type: PSBT_IN_MUSIG2_PUB_NONCE (0x1b)
    /// Key: participant_pk (33B) || aggregate_pk (33B). Value: 66-byte nonce.
    fn add_input_musig2_pub_nonce(
        &mut self,
        input_index: usize,
        participant_pk: &PublicKey,
        agg_pk: &PublicKey,
        nonce: [u8; 66],
    ) -> Result<()>;

    /// Get MuSig2 partial signatures for an input
    ///
    /// Returns list of (participant_pk, aggregate_pk, partial_sig_scalar) tuples.
    /// Field type: PSBT_IN_MUSIG2_PARTIAL_SIG (0x1c)
    fn get_input_musig2_partial_sigs(
        &self,
        input_index: usize,
    ) -> Vec<(PublicKey, PublicKey, [u8; 32])>;

    /// Add a MuSig2 partial signature for an input
    ///
    /// Field type: PSBT_IN_MUSIG2_PARTIAL_SIG (0x1c)
    /// Key: participant_pk (33B) || aggregate_pk (33B). Value: 32-byte scalar.
    fn add_input_musig2_partial_sig(
        &mut self,
        input_index: usize,
        participant_pk: &PublicKey,
        agg_pk: &PublicKey,
        sig: [u8; 32],
    ) -> Result<()>;

    // ===== Proposed BIP-375 Extension: Partial ECDH Shares =====

    /// Get partial ECDH shares for an input (proposed extension for MuSig2/FROST)
    ///
    /// Each entry represents one participant's contribution to the aggregate ECDH share.
    /// Field types: PSBT_IN_MUSIG2_PARTIAL_ECDH_SHARE (0x21) + PSBT_IN_MUSIG2_PARTIAL_DLEQ (0x22)
    fn get_input_partial_ecdh_shares(&self, input_index: usize) -> Vec<PartialEcdhShareData>;

    /// Add a partial ECDH share for an input (proposed extension for MuSig2/FROST)
    ///
    /// Writes PSBT_IN_MUSIG2_PARTIAL_ECDH_SHARE and PSBT_IN_MUSIG2_PARTIAL_DLEQ entries.
    /// Key for both: scan_key (33B) || contributor_pk (33B).
    fn add_input_partial_ecdh_share(
        &mut self,
        input_index: usize,
        partial: &PartialEcdhShareData,
    ) -> Result<()>;

    /// Remove all partial ECDH share and DLEQ entries for an input.
    ///
    /// Removes every PSBT_IN_MUSIG2_PARTIAL_ECDH_SHARE and PSBT_IN_MUSIG2_PARTIAL_DLEQ
    /// entry (one pair per contributor). Typically called after finalization to clear
    /// intermediate signing data.
    fn remove_input_partial_sp_fields(&mut self, input_index: usize) -> Result<()>;
}

impl Bip375PsbtExt for Psbt {
    fn get_global_ecdh_shares(&self) -> Vec<EcdhShareData> {
        let mut shares = Vec::new();

        for (scan_key_compressed, share_compressed) in &self.global.sp_ecdh_shares {
            // Convert CompressedPublicKey to secp256k1::PublicKey via the inner field
            let scan_key_pk = scan_key_compressed.0;
            let share_point = share_compressed.0;

            // Look for corresponding DLEQ proof
            let dleq_proof = get_global_dleq_proof(self, &scan_key_pk);
            shares.push(EcdhShareData::new(scan_key_pk, share_point, dleq_proof));
        }

        shares
    }

    fn add_global_ecdh_share(&mut self, share: &EcdhShareData) -> Result<()> {
        // Convert secp256k1::PublicKey -> bitcoin::PublicKey -> CompressedPublicKey
        let scan_key = CompressedPublicKey::try_from(bitcoin::PublicKey::new(share.scan_key))
            .map_err(|_| Error::InvalidPublicKey)?;
        let ecdh_share = CompressedPublicKey::try_from(bitcoin::PublicKey::new(share.share))
            .map_err(|_| Error::InvalidPublicKey)?;

        self.global.sp_ecdh_shares.insert(scan_key, ecdh_share);

        // Add DLEQ proof if present
        if let Some(proof) = share.dleq_proof {
            add_global_dleq_proof(self, &share.scan_key, proof)?;
        }

        Ok(())
    }

    fn get_input_ecdh_shares(&self, input_index: usize) -> Vec<EcdhShareData> {
        let Some(input) = self.inputs.get(input_index) else {
            return Vec::new();
        };

        if !is_input_eligible(input) {
            return Vec::new();
        }

        let mut shares = Vec::new();

        for (scan_key_compressed, share_compressed) in &input.sp_ecdh_shares {
            // Convert CompressedPublicKey to secp256k1::PublicKey via the inner field
            let scan_key_pk = scan_key_compressed.0;
            let share_point = share_compressed.0;

            // Look for DLEQ proof (input-specific or global)
            let dleq_proof = get_input_dleq_proof(self, input_index, &scan_key_pk)
                .or_else(|| get_global_dleq_proof(self, &scan_key_pk));
            shares.push(EcdhShareData::new(scan_key_pk, share_point, dleq_proof));
        }

        shares
    }

    fn add_input_ecdh_share(&mut self, input_index: usize, share: &EcdhShareData) -> Result<()> {
        let input = self
            .inputs
            .get_mut(input_index)
            .ok_or(Error::InvalidInputIndex(input_index))?;

        // Convert secp256k1::PublicKey -> bitcoin::PublicKey -> CompressedPublicKey
        let scan_key = CompressedPublicKey::try_from(bitcoin::PublicKey::new(share.scan_key))
            .map_err(|_| Error::InvalidPublicKey)?;
        let ecdh_share = CompressedPublicKey::try_from(bitcoin::PublicKey::new(share.share))
            .map_err(|_| Error::InvalidPublicKey)?;

        input.sp_ecdh_shares.insert(scan_key, ecdh_share);

        // Add DLEQ proof if present
        if let Some(proof) = share.dleq_proof {
            add_input_dleq_proof(self, input_index, &share.scan_key, proof)?;
        }

        Ok(())
    }

    fn get_output_sp_info(&self, output_index: usize) -> Option<(PublicKey, PublicKey)> {
        let output = self.outputs.get(output_index)?;

        if let Some(bytes) = &output.sp_v0_info {
            if bytes.len() != 66 {
                return None;
            };
            let scan_key = PublicKey::from_slice(&bytes[..33]).ok();
            let spend_key = PublicKey::from_slice(&bytes[33..]).ok();
            if let (Some(scan_key), Some(spend_key)) = (scan_key, spend_key) {
                return Some((scan_key, spend_key));
            }
        }

        None
    }

    fn set_output_sp_info(
        &mut self,
        output_index: usize,
        address: &SilentPaymentAddress,
    ) -> Result<()> {
        let output = self
            .outputs
            .get_mut(output_index)
            .ok_or(Error::InvalidOutputIndex(output_index))?;

        // PSBT_OUT_SP_V0_INFO contains only the keys (66 bytes)
        // Label is stored separately in PSBT_OUT_SP_V0_LABEL
        let mut bytes = Vec::with_capacity(66);
        bytes.extend_from_slice(&address.get_scan_key().serialize());
        bytes.extend_from_slice(&address.get_spend_key().serialize());
        output.sp_v0_info = Some(bytes);

        Ok(())
    }

    fn get_output_sp_label(&self, output_index: usize) -> Option<u32> {
        let output = self.outputs.get(output_index)?;

        if let Some(label) = output.sp_v0_label {
            return Some(label);
        }

        None
    }

    fn set_output_sp_label(&mut self, output_index: usize, label: u32) -> Result<()> {
        let output = self
            .outputs
            .get_mut(output_index)
            .ok_or(Error::InvalidOutputIndex(output_index))?;

        output.sp_v0_label = Some(label);

        Ok(())
    }

    fn get_input_sp_tweak(&self, input_index: usize) -> Option<[u8; 32]> {
        let input = self.inputs.get(input_index)?;

        for (key, value) in &input.unknowns {
            if key.type_value == PSBT_IN_SP_TWEAK && key.key.is_empty() && value.len() == 32 {
                let mut tweak = [0u8; 32];
                tweak.copy_from_slice(value);
                return Some(tweak);
            }
        }
        None
    }

    fn set_input_sp_tweak(&mut self, input_index: usize, tweak: [u8; 32]) -> Result<()> {
        let input = self
            .inputs
            .get_mut(input_index)
            .ok_or(Error::InvalidInputIndex(input_index))?;

        let key = Key {
            type_value: PSBT_IN_SP_TWEAK,
            key: vec![],
        };

        //FIXME: migrate to dedicated field in psbt_v2 once available instead of using unknowns
        input.unknowns.insert(key, tweak.to_vec());
        Ok(())
    }

    fn remove_input_sp_tweak(&mut self, input_index: usize) -> Result<()> {
        let input = self
            .inputs
            .get_mut(input_index)
            .ok_or(Error::InvalidInputIndex(input_index))?;

        let key = Key {
            type_value: PSBT_IN_SP_TWEAK,
            key: vec![],
        };

        input.unknowns.remove(&key);
        Ok(())
    }

    fn get_input_sp_spend_bip32_derivation(
        &self,
        input_index: usize,
    ) -> Option<(PublicKey, [u8; 4], Vec<u32>)> {
        let input = self.inputs.get(input_index)?;

        for (key, value) in &input.unknowns {
            if key.type_value == PSBT_IN_SP_SPEND_BIP32_DERIVATION && key.key.len() == 33 {
                // Key data is 33-byte spend public key
                let spend_pubkey = PublicKey::from_slice(&key.key).ok()?;

                // Value is fingerprint (4 bytes) + path (4 bytes per element)
                if value.len() < 4 || (value.len() - 4) % 4 != 0 {
                    return None;
                }

                let mut fingerprint = [0u8; 4];
                fingerprint.copy_from_slice(&value[0..4]);

                let path: Vec<u32> = value[4..]
                    .chunks(4)
                    .map(|chunk| u32::from_le_bytes(chunk.try_into().expect("chunk is 4 bytes")))
                    .collect();

                return Some((spend_pubkey, fingerprint, path));
            }
        }
        None
    }

    fn set_input_sp_spend_bip32_derivation(
        &mut self,
        input_index: usize,
        spend_pubkey: &PublicKey,
        fingerprint: [u8; 4],
        path: Vec<u32>,
    ) -> Result<()> {
        let input = self
            .inputs
            .get_mut(input_index)
            .ok_or(Error::InvalidInputIndex(input_index))?;

        // Key: type 0x1f with 33-byte spend pubkey as key data
        let key = Key {
            type_value: PSBT_IN_SP_SPEND_BIP32_DERIVATION,
            key: spend_pubkey.serialize().to_vec(),
        };

        // Value: fingerprint (4 bytes) + path (4 bytes per element, little-endian)
        let mut value = Vec::with_capacity(4 + path.len() * 4);
        value.extend_from_slice(&fingerprint);
        for child in &path {
            value.extend_from_slice(&child.to_le_bytes());
        }

        //FIXME: migrate to dedicated field in psbt_v2 once available instead of using unknowns
        input.unknowns.insert(key, value);
        Ok(())
    }

    fn remove_input_sp_spend_bip32_derivation(&mut self, input_index: usize) -> Result<()> {
        let input = self
            .inputs
            .get_mut(input_index)
            .ok_or(Error::InvalidInputIndex(input_index))?;

        // Find and remove the key with type 0x1f (any key data)
        let keys_to_remove: Vec<Key> = input
            .unknowns
            .keys()
            .filter(|k| k.type_value == PSBT_IN_SP_SPEND_BIP32_DERIVATION)
            .cloned()
            .collect();

        for key in keys_to_remove {
            input.unknowns.remove(&key);
        }

        Ok(())
    }

    fn num_inputs(&self) -> usize {
        self.inputs.len()
    }

    fn num_outputs(&self) -> usize {
        self.outputs.len()
    }

    fn get_input_partial_sigs(&self, input_index: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
        if let Some(input) = self.inputs.get(input_index) {
            input
                .partial_sigs
                .iter()
                .map(|(pk, sig)| (pk.inner.serialize().to_vec(), sig.to_vec()))
                .collect()
        } else {
            Vec::new()
        }
    }

    fn get_output_scan_keys(&self) -> Vec<PublicKey> {
        let mut scan_keys = Vec::new();
        for output_idx in 0..self.outputs.len() {
            if let Some(sp_info) = self.get_output_sp_info(output_idx) {
                scan_keys.push(sp_info.0);
            }
        }
        scan_keys
    }

    fn get_input_musig2_participant_pubkeys(
        &self,
        input_index: usize,
    ) -> Vec<(PublicKey, Vec<PublicKey>)> {
        let Some(input) = self.inputs.get(input_index) else {
            return Vec::new();
        };

        let mut result = Vec::new();
        for (agg_key_compressed, participants_bytes) in &input.musig2_participant_pubkeys {
            let agg_pk = agg_key_compressed.0;
            let mut participants = Vec::new();
            for chunk in participants_bytes.chunks(33) {
                if let Ok(pk) = PublicKey::from_slice(chunk) {
                    participants.push(pk);
                }
            }
            result.push((agg_pk, participants));
        }
        result
    }

    fn set_input_musig2_participant_pubkeys(
        &mut self,
        input_index: usize,
        agg_pk: &PublicKey,
        participants: &[PublicKey],
    ) -> Result<()> {
        let input = self
            .inputs
            .get_mut(input_index)
            .ok_or(Error::InvalidInputIndex(input_index))?;

        let agg_compressed = CompressedPublicKey::try_from(bitcoin::PublicKey::new(*agg_pk))
            .map_err(|_| Error::InvalidPublicKey)?;

        let mut value = Vec::with_capacity(participants.len() * 33);
        for pk in participants {
            value.extend_from_slice(&pk.serialize());
        }

        input
            .musig2_participant_pubkeys
            .insert(agg_compressed, value);
        Ok(())
    }

    fn get_output_musig2_participant_pubkeys(
        &self,
        output_index: usize,
    ) -> Vec<(PublicKey, Vec<PublicKey>)> {
        let Some(output) = self.outputs.get(output_index) else {
            return Vec::new();
        };

        let mut result = Vec::new();
        for (agg_key_compressed, participants_bytes) in &output.musig2_participant_pubkeys {
            let agg_pk = agg_key_compressed.0;
            let mut participants = Vec::new();
            for chunk in participants_bytes.chunks(33) {
                if let Ok(pk) = PublicKey::from_slice(chunk) {
                    participants.push(pk);
                }
            }
            result.push((agg_pk, participants));
        }
        result
    }

    fn set_output_musig2_participant_pubkeys(
        &mut self,
        output_index: usize,
        agg_pk: &PublicKey,
        participants: &[PublicKey],
    ) -> Result<()> {
        let output = self
            .outputs
            .get_mut(output_index)
            .ok_or(Error::InvalidOutputIndex(output_index))?;

        let agg_compressed = CompressedPublicKey::try_from(bitcoin::PublicKey::new(*agg_pk))
            .map_err(|_| Error::InvalidPublicKey)?;

        let mut value = Vec::with_capacity(participants.len() * 33);
        for pk in participants {
            value.extend_from_slice(&pk.serialize());
        }

        output
            .musig2_participant_pubkeys
            .insert(agg_compressed, value);
        Ok(())
    }

    fn get_input_musig2_pub_nonces(
        &self,
        input_index: usize,
    ) -> Vec<(PublicKey, PublicKey, [u8; 66])> {
        let Some(input) = self.inputs.get(input_index) else {
            return Vec::new();
        };

        let mut result = Vec::new();
        for (compound_key, nonce_bytes) in &input.musig2_pub_nonces {
            if compound_key.len() == 66 && nonce_bytes.len() == 66 {
                if let (Ok(participant_pk), Ok(agg_pk)) = (
                    PublicKey::from_slice(&compound_key[..33]),
                    PublicKey::from_slice(&compound_key[33..]),
                ) {
                    let mut nonce = [0u8; 66];
                    nonce.copy_from_slice(nonce_bytes);
                    result.push((participant_pk, agg_pk, nonce));
                }
            }
        }
        result
    }

    fn add_input_musig2_pub_nonce(
        &mut self,
        input_index: usize,
        participant_pk: &PublicKey,
        agg_pk: &PublicKey,
        nonce: [u8; 66],
    ) -> Result<()> {
        let input = self
            .inputs
            .get_mut(input_index)
            .ok_or(Error::InvalidInputIndex(input_index))?;

        let mut compound_key = Vec::with_capacity(66);
        compound_key.extend_from_slice(&participant_pk.serialize());
        compound_key.extend_from_slice(&agg_pk.serialize());

        input.musig2_pub_nonces.insert(compound_key, nonce.to_vec());
        Ok(())
    }

    fn get_input_musig2_partial_sigs(
        &self,
        input_index: usize,
    ) -> Vec<(PublicKey, PublicKey, [u8; 32])> {
        let Some(input) = self.inputs.get(input_index) else {
            return Vec::new();
        };

        let mut result = Vec::new();
        for (compound_key, sig_bytes) in &input.musig2_partial_sigs {
            if compound_key.len() == 66 && sig_bytes.len() == 32 {
                if let (Ok(participant_pk), Ok(agg_pk)) = (
                    PublicKey::from_slice(&compound_key[..33]),
                    PublicKey::from_slice(&compound_key[33..]),
                ) {
                    let mut sig = [0u8; 32];
                    sig.copy_from_slice(sig_bytes);
                    result.push((participant_pk, agg_pk, sig));
                }
            }
        }
        result
    }

    fn add_input_musig2_partial_sig(
        &mut self,
        input_index: usize,
        participant_pk: &PublicKey,
        agg_pk: &PublicKey,
        sig: [u8; 32],
    ) -> Result<()> {
        let input = self
            .inputs
            .get_mut(input_index)
            .ok_or(Error::InvalidInputIndex(input_index))?;

        let mut compound_key = Vec::with_capacity(66);
        compound_key.extend_from_slice(&participant_pk.serialize());
        compound_key.extend_from_slice(&agg_pk.serialize());

        input.musig2_partial_sigs.insert(compound_key, sig.to_vec());
        Ok(())
    }

    fn get_input_partial_ecdh_shares(&self, input_index: usize) -> Vec<PartialEcdhShareData> {
        let Some(input) = self.inputs.get(input_index) else {
            return Vec::new();
        };

        // Collect partial shares keyed by (scan_key_bytes || contributor_pk_bytes)
        let mut shares_map: std::collections::HashMap<Vec<u8>, (PublicKey, PublicKey, PublicKey)> =
            std::collections::HashMap::new();

        for (key, value) in &input.unknowns {
            if key.type_value == PSBT_IN_MUSIG2_PARTIAL_ECDH_SHARE
                && key.key.len() == 66
                && value.len() == 33
            {
                if let (Ok(scan_key), Ok(contributor_pk), Ok(share)) = (
                    PublicKey::from_slice(&key.key[..33]),
                    PublicKey::from_slice(&key.key[33..]),
                    PublicKey::from_slice(value),
                ) {
                    shares_map
                        .entry(key.key.clone())
                        .or_insert((scan_key, contributor_pk, share));
                }
            }
        }

        // Match with DLEQ proofs
        let mut result = Vec::new();
        for (compound_key_bytes, (scan_key, contributor_pk, share)) in shares_map {
            let dleq_key = Key {
                type_value: PSBT_IN_MUSIG2_PARTIAL_DLEQ,
                key: compound_key_bytes,
            };
            if let Some(dleq_bytes) = input.unknowns.get(&dleq_key) {
                if let Ok(arr) = <[u8; 64]>::try_from(dleq_bytes.as_slice()) {
                    result.push(PartialEcdhShareData {
                        scan_key,
                        contributor_pk,
                        share,
                        dleq_proof: DleqProof(arr),
                    });
                }
            }
        }
        result
    }

    fn add_input_partial_ecdh_share(
        &mut self,
        input_index: usize,
        partial: &PartialEcdhShareData,
    ) -> Result<()> {
        let input = self
            .inputs
            .get_mut(input_index)
            .ok_or(Error::InvalidInputIndex(input_index))?;

        // Compound key: scan_key (33B) || contributor_pk (33B)
        let mut compound_key = Vec::with_capacity(66);
        compound_key.extend_from_slice(&partial.scan_key.serialize());
        compound_key.extend_from_slice(&partial.contributor_pk.serialize());

        // Write partial ECDH share
        let share_key = Key {
            type_value: PSBT_IN_MUSIG2_PARTIAL_ECDH_SHARE,
            key: compound_key.clone(),
        };
        input
            .unknowns
            .insert(share_key, partial.share.serialize().to_vec());

        // Write DLEQ proof
        let dleq_key = Key {
            type_value: PSBT_IN_MUSIG2_PARTIAL_DLEQ,
            key: compound_key,
        };
        input
            .unknowns
            .insert(dleq_key, partial.dleq_proof.as_bytes().to_vec());

        Ok(())
    }

    fn remove_input_partial_sp_fields(&mut self, input_index: usize) -> Result<()> {
        let input = self
            .inputs
            .get_mut(input_index)
            .ok_or(Error::InvalidInputIndex(input_index))?;

        let keys_to_remove: Vec<Key> = input
            .unknowns
            .keys()
            .filter(|k| {
                k.type_value == PSBT_IN_MUSIG2_PARTIAL_ECDH_SHARE
                    || k.type_value == PSBT_IN_MUSIG2_PARTIAL_DLEQ
            })
            .cloned()
            .collect();

        for key in keys_to_remove {
            input.unknowns.remove(&key);
        }

        Ok(())
    }
}

// Private helper functions for DLEQ proof management
fn get_global_dleq_proof(psbt: &Psbt, scan_key: &PublicKey) -> Option<DleqProof> {
    let scan_key_compressed =
        CompressedPublicKey::try_from(bitcoin::PublicKey::new(*scan_key)).ok()?;
    psbt.global
        .sp_dleq_proofs
        .get(&scan_key_compressed)
        .copied()
}

fn add_global_dleq_proof(psbt: &mut Psbt, scan_key: &PublicKey, proof: DleqProof) -> Result<()> {
    let scan_key_compressed = CompressedPublicKey::try_from(bitcoin::PublicKey::new(*scan_key))
        .map_err(|_| Error::InvalidPublicKey)?;

    psbt.global
        .sp_dleq_proofs
        .insert(scan_key_compressed, proof);

    Ok(())
}

fn get_input_dleq_proof(
    psbt: &Psbt,
    input_index: usize,
    scan_key: &PublicKey,
) -> Option<DleqProof> {
    let input = psbt.inputs.get(input_index)?;
    let scan_key_compressed =
        CompressedPublicKey::try_from(bitcoin::PublicKey::new(*scan_key)).ok()?;

    input.sp_dleq_proofs.get(&scan_key_compressed).copied()
}

fn add_input_dleq_proof(
    psbt: &mut Psbt,
    input_index: usize,
    scan_key: &PublicKey,
    proof: DleqProof,
) -> Result<()> {
    let input = psbt
        .inputs
        .get_mut(input_index)
        .ok_or(Error::InvalidInputIndex(input_index))?;

    let scan_key_compressed = CompressedPublicKey::try_from(bitcoin::PublicKey::new(*scan_key))
        .map_err(|_| Error::InvalidPublicKey)?;

    input.sp_dleq_proofs.insert(scan_key_compressed, proof);

    Ok(())
}

// ============================================================================
// Convenience Accessor Functions
// ============================================================================
//
// These provide ergonomic access patterns for common PSBT field operations.

/// Get the transaction ID (TXID) for an input
pub fn get_input_txid(psbt: &SilentPaymentPsbt, input_idx: usize) -> Result<Txid> {
    let input = psbt
        .inputs
        .get(input_idx)
        .ok_or_else(|| Error::InvalidInputIndex(input_idx))?;

    // PSBT v2 inputs have explicit previous_txid field
    Ok(input.previous_txid)
}

/// Get the output index (vout) for an input
pub fn get_input_vout(psbt: &SilentPaymentPsbt, input_idx: usize) -> Result<u32> {
    let input = psbt
        .inputs
        .get(input_idx)
        .ok_or_else(|| Error::InvalidInputIndex(input_idx))?;

    Ok(input.spent_output_index)
}

/// Get the outpoint (TXID + vout) for an input as raw bytes
pub fn get_input_outpoint_bytes(psbt: &SilentPaymentPsbt, input_idx: usize) -> Result<Vec<u8>> {
    let txid = get_input_txid(psbt, input_idx)?;
    let vout = get_input_vout(psbt, input_idx)?;

    let mut outpoint = Vec::with_capacity(36);
    outpoint.extend_from_slice(&txid[..]);
    outpoint.extend_from_slice(&vout.to_le_bytes());
    Ok(outpoint)
}

/// Get the outpoint (TXID + vout) for an input as a typed OutPoint
pub fn get_input_outpoint(psbt: &SilentPaymentPsbt, input_idx: usize) -> Result<OutPoint> {
    let txid = get_input_txid(psbt, input_idx)?;
    let vout = get_input_vout(psbt, input_idx)?;
    Ok(OutPoint { txid, vout })
}

/// Get input public key from PSBT fields with fallback priority
///
/// Tries multiple sources in this order:
/// 1. SP spend BIP32 derivation (for Silent Payment inputs, highest priority)
/// 2. Standard BIP32 derivation field (for non-Taproot)
/// 3. Witness utxo (for Taproot)
pub fn get_input_pubkey(psbt: &SilentPaymentPsbt, input_idx: usize) -> Result<PublicKey> {
    let input = psbt
        .inputs
        .get(input_idx)
        .ok_or_else(|| Error::InvalidInputIndex(input_idx))?;

    // Method 1: Extract from SP spend BIP32 derivation (for Silent Payment inputs)
    if let Some((spend_pubkey, _, _)) = psbt.get_input_sp_spend_bip32_derivation(input_idx) {
        return Ok(spend_pubkey);
    }

    // Method 2: Extract from BIP32 derivation field (for non-Taproot)
    if !input.bip32_derivations.is_empty() {
        // Return the first key
        if let Some(key) = input.bip32_derivations.keys().next() {
            return Ok(key.inner);
        }
    }

    // Method 3: Extract from Witness utxo (for Taproot inputs)
    if let Some(witness_utxo) = input.witness_utxo.as_ref() {
        if witness_utxo.script_pubkey.is_p2tr() {
            if let Ok(x_only) = bitcoin::key::XOnlyPublicKey::from_slice(
                &witness_utxo.script_pubkey.as_bytes()[2..34],
            ) {
                return Ok(x_only.public_key(silentpayments::secp256k1::Parity::Even));
            }
        }
    }

    Err(Error::Other(format!(
        "Input {} missing public key (no SP spend, witness utxo or BIP32 derivations found)",
        input_idx
    )))
}

pub fn get_output_sp_keys(
    psbt: &SilentPaymentPsbt,
    output_idx: usize,
) -> Result<(PublicKey, PublicKey)> {
    // Use the extension trait method via SilentPaymentPsbt wrapper
    let sp_info = psbt.get_output_sp_info(output_idx).ok_or_else(|| {
        Error::MissingField(format!("Output {} missing PSBT_OUT_SP_V0_INFO", output_idx))
    })?;
    Ok((sp_info.0, sp_info.1))
}

// ============================================================================
// Display Extension Traits
// ============================================================================
//
// The following traits provide methods for extracting and serializing PSBT fields
// for display purposes. These are used by GUI and analysis tools to inspect PSBT contents.

/// Extension trait for iterating all PSBT global map fields as raw (type, key, value) tuples.
///
/// Delegates to psbt_v2's internal serialization path, so all fields — including unknowns
/// and any future additions to psbt_v2 — are returned automatically in serialization order.
pub trait GlobalFieldsExt {
    /// Returns all global map fields as (field_type, key_data, value_data) tuples.
    fn iter_global_fields(&self) -> Vec<(u64, Vec<u8>, Vec<u8>)>;
}

impl GlobalFieldsExt for psbt_v2::v2::Global {
    fn iter_global_fields(&self) -> Vec<(u64, Vec<u8>, Vec<u8>)> {
        self.pairs()
            .into_iter()
            .map(|pair| (pair.key.type_value, pair.key.key, pair.value))
            .collect()
    }
}

/// Extension trait for iterating all PSBT input map fields as raw (type, key, value) tuples.
///
/// Delegates to psbt_v2's internal serialization path, so all fields — including unknowns
/// and any future additions to psbt_v2 — are returned automatically in serialization order.
pub trait InputFieldsExt {
    /// Returns all input map fields as (field_type, key_data, value_data) tuples.
    fn iter_input_fields(&self) -> Vec<(u64, Vec<u8>, Vec<u8>)>;
}

impl InputFieldsExt for psbt_v2::v2::Input {
    fn iter_input_fields(&self) -> Vec<(u64, Vec<u8>, Vec<u8>)> {
        self.pairs()
            .into_iter()
            .map(|pair| (pair.key.type_value, pair.key.key, pair.value))
            .collect()
    }
}

/// Extension trait for iterating all PSBT output map fields as raw (type, key, value) tuples.
///
/// Delegates to psbt_v2's internal serialization path, so all fields — including unknowns
/// and any future additions to psbt_v2 — are returned automatically in serialization order.
pub trait OutputFieldsExt {
    /// Returns all output map fields as (field_type, key_data, value_data) tuples.
    fn iter_output_fields(&self) -> Vec<(u64, Vec<u8>, Vec<u8>)>;
}

impl OutputFieldsExt for psbt_v2::v2::Output {
    fn iter_output_fields(&self) -> Vec<(u64, Vec<u8>, Vec<u8>)> {
        self.pairs()
            .into_iter()
            .map(|pair| (pair.key.type_value, pair.key.key, pair.value))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Secp256k1, SecretKey};

    fn create_test_psbt() -> Psbt {
        // Create a minimal valid PSBT v2
        Psbt {
            global: psbt_v2::v2::Global::default(),
            inputs: vec![],
            outputs: vec![],
        }
    }

    #[test]
    fn test_global_ecdh_share() {
        let mut psbt = create_test_psbt();

        let secp = Secp256k1::new();
        let scan_key =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[1u8; 32]).unwrap());
        let share_point =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[2u8; 32]).unwrap());

        let share = EcdhShareData::without_proof(scan_key, share_point);

        // Add share
        psbt.add_global_ecdh_share(&share).unwrap();

        // Retrieve shares
        let shares = psbt.get_global_ecdh_shares();
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].scan_key, scan_key);
        assert_eq!(shares[0].share, share_point);
    }

    #[test]
    fn test_global_dleq_proof() {
        let mut psbt = create_test_psbt();

        let secp = Secp256k1::new();
        let scan_key =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[1u8; 32]).unwrap());
        let proof = DleqProof([0x42u8; 64]);

        // Add proof
        add_global_dleq_proof(&mut psbt, &scan_key, proof).unwrap();

        // Retrieve proof
        let retrieved = get_global_dleq_proof(&psbt, &scan_key);
        assert_eq!(retrieved, Some(proof));
    }

    #[test]
    fn test_output_sp_address() {
        let mut psbt = create_test_psbt();
        psbt.outputs.push(psbt_v2::v2::Output::default());

        let secp = Secp256k1::new();
        let scan_key =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[1u8; 32]).unwrap());
        let spend_key =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[2u8; 32]).unwrap());

        let address =
            SilentPaymentAddress::new(scan_key, spend_key, silentpayments::Network::Regtest, silentpayments::SpVersion::ZERO);

        // Set address
        psbt.set_output_sp_info(0, &address).unwrap();

        // Retrieve address
        let retrieved = psbt.get_output_sp_info(0);
        assert_eq!(
            retrieved.map(|res| (res.0, res.1)),
            Some((address.get_scan_key(), address.get_spend_key()))
        );
    }

    #[test]
    fn test_output_sp_label() {
        let mut psbt = create_test_psbt();
        psbt.outputs.push(psbt_v2::v2::Output::default());

        let label = 42u32;

        // Set label
        psbt.set_output_sp_label(0, label).unwrap();

        // Retrieve label
        let retrieved = psbt.get_output_sp_label(0);
        assert_eq!(retrieved, Some(label));
    }
}

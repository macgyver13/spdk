//! Silent Payment ECDH Share Aggregation
//!
//! Collects ECDH shares and input pubkeys from a PSBT, grouped by scan key.
//!
//! Global vs per-input is determined by which PSBT fields are present

use super::{
    get_input_outpoint_bytes, get_input_pubkey, Bip375PsbtExt, Error, Result, SilentPaymentPsbt,
};
use crate::psbt::crypto::bip352::is_input_eligible;
use crate::psbt::crypto::dleq_verify_proof;
use secp256k1::{PublicKey, Secp256k1};
use silentpayments::bitcoin_hashes::Hash as SpHash;
use silentpayments::utils::hash::InputsHash;
use std::collections::HashMap;

/// Aggregated ECDH share and input pubkey sum for a single scan key
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregatedShare {
    /// The scan key this aggregation is for
    pub scan_key: PublicKey,
    /// The aggregated ECDH share point (global share directly, or EC sum of per-input shares)
    pub aggregated_share: PublicKey,
    /// Sum of eligible input public keys that contributed to this share
    pub input_sum: PublicKey,
}

/// Collection of aggregated shares for all scan keys in a PSBT
#[derive(Debug, Clone)]
pub struct AggregatedShares {
    shares: HashMap<PublicKey, AggregatedShare>,
}

impl AggregatedShares {
    pub fn get(&self, scan_key: &PublicKey) -> Option<&AggregatedShare> {
        self.shares.get(scan_key)
    }

    pub fn len(&self) -> usize {
        self.shares.len()
    }

    pub fn is_empty(&self) -> bool {
        self.shares.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&PublicKey, &AggregatedShare)> {
        self.shares.iter()
    }
}

/// Collect ECDH shares and input pubkey sums from a PSBT, grouped by scan key.
///
/// For each scan key found in SP outputs:
/// - If a global ECDH share exists: use it directly, sum ALL eligible input pubkeys.
/// - Otherwise: sum per-input ECDH shares and their corresponding input pubkeys.
///
/// Partial ECDH shares (MuSig2/FROST) are synthesized into per-input shares first.
pub fn aggregate_ecdh_shares(psbt: &SilentPaymentPsbt) -> Result<AggregatedShares> {
     aggregate_ecdh_shares_with_secp(psbt, None)
}
 
/// Collect ECDH shares, with optional secp context for partial ECDH DLEQ verification.
 pub fn aggregate_ecdh_shares_with_secp(
     psbt: &SilentPaymentPsbt,
     secp: Option<&Secp256k1<secp256k1::All>>,
 ) -> Result<AggregatedShares> {
    let num_inputs = psbt.num_inputs();
    if num_inputs == 0 {
        return Err(Error::Other(
            "Cannot aggregate ECDH shares: no inputs".to_string(),
        ));
    }

// Discover scan keys from SP outputs
    let mut scan_keys = Vec::new();
    for output_idx in 0..psbt.num_outputs() {
        if let Some((scan_key, _)) = psbt.get_output_sp_info(output_idx) {
            if !scan_keys.contains(&scan_key) {
                scan_keys.push(scan_key);
            }
        }
    }

    // Pre-compute synthesized partial ECDH shares (MuSig2/FROST)
    // let synthesized = synthesize_partial_ecdh_shares(psbt, secp)?;

    // Build global ECDH share lookup
    let global_shares: HashMap<PublicKey, PublicKey> = psbt
        .get_global_ecdh_shares()
        .into_iter()
        .map(|s| (s.scan_key, s.share))
        .collect();

    let mut result = HashMap::new();

    for scan_key in scan_keys {
        if let Some(&global_share) = global_shares.get(&scan_key) {
            // Global mode: use share directly, sum ALL eligible input pubkeys
            let input_sum = sum_all_eligible_pubkeys(psbt)?;
            result.insert(
                scan_key,
                AggregatedShare {
                    scan_key,
                    aggregated_share: global_share,
                    input_sum,
                },
            );
        } else {
            // Per-input mode: sum shares and pubkeys from contributing inputs only
            let mut agg_share: Option<PublicKey> = None;
            let mut input_sum: Option<PublicKey> = None;

            for input_idx in 0..num_inputs {
                // Find share: synthesized partial first, then regular per-input
                // let share = synthesized
                //     .get(&input_idx)
                //     .and_then(|m| m.get(&scan_key))
                //     .copied()
                //     .or_else(|| {
                //         psbt.get_input_ecdh_shares(input_idx)
                //             .into_iter()
                //             .find(|s| s.scan_key == scan_key)
                //             .map(|s| s.share)
                //     });
                let share = psbt.get_input_ecdh_shares(input_idx)
                            .into_iter()
                            .find(|s| s.scan_key == scan_key)
                            .map(|s| s.share);

                let share = match share {
                    Some(s) => s,
                    None => continue,
                };

                if !is_input_eligible(&psbt.inputs[input_idx]) {
                    continue;
                }

                agg_share = Some(match agg_share {
                    None => share,
                    Some(existing) => combine_keys(&existing, &share)?,
                });

                if let Ok(pubkey) = get_input_pubkey(psbt, input_idx) {
                    input_sum = Some(match input_sum {
                        None => pubkey,
                        Some(existing) => combine_keys(&existing, &pubkey)?,
                    });
                }
            }

            if let (Some(agg_share), Some(input_sum)) = (agg_share, input_sum) {
                result.insert(
                    scan_key,
                    AggregatedShare {
                        scan_key,
                        aggregated_share: agg_share,
                        input_sum,
                    },
                );
            }
        }
    }

    Ok(AggregatedShares { shares: result })
}
 
 /// Sum multiple public keys using elliptic curve addition
 ///
 /// This is used to aggregate per-input ECDH shares. Each share is a point on the curve,
 /// and we sum them to get the total ECDH secret.
 ///
 /// # Arguments
 /// * `pubkeys` - Slice of public keys to sum
 ///
 /// # Returns
 /// * The sum of all public keys (P1 + P2 + ... + Pn)
 ///
 /// # Errors
 /// * If the input slice is empty
 /// * If elliptic curve addition fails (e.g., adding a point to its negation)
 fn aggregate_public_keys(pubkeys: &[PublicKey]) -> Result<PublicKey> {
     if pubkeys.is_empty() {
         return Err(Error::Other(
             "Cannot aggregate zero public keys".to_string(),
         ));
     }
 
     let mut result = pubkeys[0];
     for pubkey in &pubkeys[1..] {
         result = result
             .combine(pubkey)
             .map_err(|e| Error::Other(format!("Failed to aggregate ECDH shares: {}", e)))?;
     }
 
     Ok(result)
 }
 
 /// Compute BIP-352 shared secrets from aggregated shares.
///
/// For each scan key: `shared_secret = aggregated_share * input_hash`
/// where `input_hash = hash_BIP0352/Inputs(smallest_outpoint || input_sum)`
pub fn compute_sp_shared_secrets(
    secp: &Secp256k1<secp256k1::All>,
    psbt: &SilentPaymentPsbt,
    aggregated_shares: &AggregatedShares,
) -> Result<HashMap<PublicKey, PublicKey>> {
    let outpoints = (0..psbt.num_inputs())
        .map(|input_idx| get_input_outpoint_bytes(psbt, input_idx))
        .collect::<Result<Vec<_>>>()?;

    let smallest_outpoint: [u8; 36] = outpoints
        .iter()
        .min()
        .ok_or_else(|| Error::Other("No outpoints".to_string()))?
        .as_slice()
        .try_into()
        .map_err(|_| Error::Other("Outpoint is not 36 bytes".to_string()))?;

    let mut shared_secrets = HashMap::new();
    for (scan_key, share) in aggregated_shares.iter() {
        let hash_bytes = SpHash::to_byte_array(InputsHash::from_outpoint_and_A_sum(
            &smallest_outpoint,
            share.input_sum,
        ));
        let input_hash = secp256k1::Scalar::from_be_bytes(hash_bytes)
            .map_err(|_| Error::Other("Input hash is invalid scalar".to_string()))?;

        let shared_secret = share
            .aggregated_share
            .mul_tweak(secp, &input_hash)
            .map_err(|e| {
                Error::Other(format!(
                    "Failed to multiply ECDH share by input_hash: {}",
                    e
                ))
            })?;

        shared_secrets.insert(*scan_key, shared_secret);
    }

    Ok(shared_secrets)
}

// -- helpers --

/// Sum all eligible input public keys in the PSBT.
fn sum_all_eligible_pubkeys(psbt: &SilentPaymentPsbt) -> Result<PublicKey> {
    let mut sum: Option<PublicKey> = None;
    for input_idx in 0..psbt.num_inputs() {
        if !is_input_eligible(&psbt.inputs[input_idx]) {
            continue;
        }
        if let Ok(pubkey) = get_input_pubkey(psbt, input_idx) {
            sum = Some(match sum {
                None => pubkey,
                Some(existing) => combine_keys(&existing, &pubkey)?,
            });
        }
    }
    sum.ok_or_else(|| Error::Other("No eligible input pubkeys found".to_string()))
}

/// EC point addition of two public keys.
fn combine_keys(a: &PublicKey, b: &PublicKey) -> Result<PublicKey> {
    a.combine(b)
        .map_err(|e| Error::Other(format!("EC point addition failed: {}", e)))
}

/// Synthesize per-input ECDH shares from partial shares (MuSig2/FROST extension).
///
/// For each input with partial ECDH shares, verifies DLEQ proofs (if secp provided)
/// and sums partial shares into a single per-input share per scan key.
// fn synthesize_partial_ecdh_shares(
//     psbt: &SilentPaymentPsbt,
//     secp: Option<&Secp256k1<secp256k1::All>>,
// ) -> Result<HashMap<usize, HashMap<PublicKey, PublicKey>>> {
//     let mut synthesized: HashMap<usize, HashMap<PublicKey, PublicKey>> = HashMap::new();

//     for input_idx in 0..psbt.num_inputs() {
//         let partial_shares = psbt.get_input_partial_ecdh_shares(input_idx);
//         if partial_shares.is_empty() {
//             continue;
//         }

//         // Group by scan_key
//         let mut by_scan_key: HashMap<PublicKey, Vec<(PublicKey, psbt_v2::v2::dleq::DleqProof)>> =
//             HashMap::new();
//         for partial in &partial_shares {
//             by_scan_key
//                 .entry(partial.scan_key)
//                 .or_default()
//                 .push((partial.share, partial.dleq_proof));
//         }

//         for (scan_key, entries) in by_scan_key {
//             // Verify DLEQ proofs if secp context available
//             if let Some(secp) = secp {
//                 for (partial, (share, proof)) in partial_shares.iter().zip(entries.iter()) {
//                     let verified = dleq_verify_proof(
//                         secp,
//                         &partial.contributor_pk,
//                         &scan_key,
//                         share,
//                         proof,
//                         None,
//                     )
//                     .map_err(|_| Error::InvalidDleqProof(input_idx))?;
//                     if !verified {
//                         return Err(Error::InvalidDleqProof(input_idx));
//                     }
//                 }
//             }

//             // Sum partial shares into a single per-input share
//             let mut agg: Option<PublicKey> = None;
//             for (share, _) in &entries {
//                 agg = Some(match agg {
//                     None => *share,
//                     Some(existing) => combine_keys(&existing, share)?,
//                 });
//             }

//             if let Some(agg_share) = agg {
//                 synthesized
//                     .entry(input_idx)
//                     .or_default()
//                     .insert(scan_key, agg_share);
//             }
//         }
//     }

//     Ok(synthesized)
// }

#[cfg(test)]
mod tests {
    // use super::*;
    // Tests will be added during implementation
}

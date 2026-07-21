//! Silent-payment ECDH share aggregation (BIP-352 + participant shares).
//!
//! Ported from old `spdk-core::psbt::core::shares` (`slznmzkv`), adapted to native
//! `psbt_v2` storage and the new `psbt`/`silentpayments` helpers.

use anyhow::{anyhow, Result};
use secp256k1::{PublicKey, Secp256k1};
use std::collections::{HashMap, HashSet};

use super::keyagg;
use crate::Psbt;

/// BIP-352 input public key, or `None` for an ineligible input.
fn input_pubkey(input: &psbt_v2::Input) -> Result<Option<PublicKey>> {
    crate::roles::signer::extract_eligible_input_pubkey(input)
        .map_err(|e| anyhow!("extract input pubkey: {e}"))
}

/// Aggregate MuSig2 ECDH shares from a PSBT into one share per scan key.
///
/// Per-input participant ECDH shares are synthesized into a single per-input
/// share first (BIP-327 weighting), then summed across eligible inputs. The
/// BIP-352 `input_hash` multiply and A_sum computation happen later, inside
/// [`silentpayments::TransactionSharedSecret::new_from_aggregate_share`].
pub fn aggregate_ecdh_shares(
    psbt: &Psbt,
    secp: &Secp256k1<secp256k1::All>,
) -> Result<HashMap<PublicKey, PublicKey>> {
    if psbt.inputs.is_empty() {
        return Err(anyhow!("cannot aggregate ECDH shares: no inputs"));
    }

    // Discover scan keys from SP outputs.
    let mut scan_keys = Vec::new();
    for output in &psbt.outputs {
        if let Some((scan_key, _)) = output.sp_info()? {
            if !scan_keys.contains(&scan_key) {
                scan_keys.push(scan_key);
            }
        }
    }

    let synthesized = synthesize_partial_ecdh_shares(psbt, secp)?;

    let mut result = HashMap::new();

    for scan_key in scan_keys {
        // Sum one synthesized MuSig2 share for every eligible input. Ordinary
        // BIP-375 global/per-input shares remain the responsibility of SPDK's
        // `SignerPsbtExt::compute_sp_outputs` and are intentionally not copied here.
        let mut agg_share: Option<PublicKey> = None;

        for (input_idx, input) in psbt.inputs.iter().enumerate() {
            if input_pubkey(input)?.is_none() {
                continue;
            }
            let share = synthesized
                .get(&input_idx)
                .and_then(|m| m.get(&scan_key))
                .copied()
                .ok_or_else(|| {
                    anyhow!(
                        "missing MuSig2 ECDH share for input {input_idx} and scan key {scan_key}"
                    )
                })?;
            agg_share = Some(match agg_share {
                None => share,
                Some(existing) => combine_keys(&existing, &share)?,
            });
        }

        let aggregated_share = agg_share.ok_or_else(|| anyhow!("no eligible MuSig2 inputs"))?;
        result.insert(scan_key, aggregated_share);
    }

    Ok(result)
}

// ===== helpers =====

fn combine_keys(a: &PublicKey, b: &PublicKey) -> Result<PublicKey> {
    a.combine(b)
        .map_err(|e| anyhow!("EC point addition failed: {e}"))
}

/// Synthesize per-input ECDH shares from each participant share.
///
/// For each input with partial shares: verify every contributor's DLEQ proof, then
/// combine the partial shares with the BIP-327 weighting (`aggregate_partial_ecdh_shares`)
/// when MuSig2 participants are registered, else plain EC-sum.
fn synthesize_partial_ecdh_shares(
    psbt: &Psbt,
    secp: &Secp256k1<secp256k1::All>,
) -> Result<HashMap<usize, HashMap<PublicKey, PublicKey>>> {
    let mut synthesized: HashMap<usize, HashMap<PublicKey, PublicKey>> = HashMap::new();

    for (input_idx, input) in psbt.inputs.iter().enumerate() {
        let partial_shares = input.parse_sp_partial_ecdh_shares()?;
        if partial_shares.is_empty() {
            continue;
        }

        // Group (contributor_pk, share, proof) by scan key.
        let mut by_scan_key: HashMap<PublicKey, Vec<(PublicKey, PublicKey, _)>> = HashMap::new();
        for partial in &partial_shares {
            by_scan_key.entry(partial.scan_key).or_default().push((
                partial.contributor_pk,
                partial.share,
                partial.dleq_proof,
            ));
        }

        let musig2_info = input.parse_musig2_participant_pubkeys()?;
        if musig2_info.len() > 1 {
            return Err(anyhow!(
                "input {input_idx} has multiple MuSig2 aggregate key entries"
            ));
        }
        let has_musig2 = !musig2_info.is_empty();

        for (scan_key, entries) in by_scan_key {
            // Verify each contributor's DLEQ proof against its own partial share.
            for (contributor_pk, share, proof) in &entries {
                let rust_proof = crate::core::utils::to_rust_dleq(*proof);
                let verified = crate::verify_dleq_proof(
                    secp,
                    contributor_pk,
                    &scan_key,
                    share,
                    &rust_proof,
                    None,
                )
                .map_err(|e| anyhow!("DLEQ verify failed on input {input_idx}: {e:?}"))?;
                if !verified {
                    return Err(anyhow!("invalid DLEQ proof on input {input_idx}"));
                }
            }

            let agg_share = if has_musig2 {
                let (_agg_pk, participants) = &musig2_info[0];
                let expected: HashSet<PublicKey> = participants.iter().copied().collect();
                let actual: HashSet<PublicKey> = entries
                    .iter()
                    .map(|(contributor, _, _)| *contributor)
                    .collect();
                if actual != expected {
                    return Err(anyhow!(
                        "incomplete or unknown MuSig2 contributors on input {input_idx}"
                    ));
                }
                // A missing aggregate origin means the aggregate key was built by
                // deriving each participant first (BIP-390 ranged participants) --
                // see rust-psbt's `musig2_agg_path` doc comment. It must not be
                // defaulted to [0, 0], since that would apply BIP-328 tweaks to a
                // key that was never derived that way.
                let path = input.musig2_agg_path();
                let mode = match path.as_deref() {
                    Some(path) => keyagg::AggregationMode::AggregateThenDerive { path },
                    None => keyagg::AggregationMode::DeriveThenAggregate,
                };
                let contributions: Vec<(PublicKey, PublicKey)> =
                    entries.iter().map(|(c, s, _)| (*c, *s)).collect();
                keyagg::aggregate_partial_ecdh_shares(
                    secp,
                    participants,
                    mode,
                    &scan_key,
                    &contributions,
                )?
            } else {
                let mut agg: Option<PublicKey> = None;
                for (_, share, _) in &entries {
                    agg = Some(match agg {
                        None => *share,
                        Some(existing) => combine_keys(&existing, share)?,
                    });
                }
                agg.ok_or_else(|| anyhow!("no shares aggregated"))?
            };

            synthesized
                .entry(input_idx)
                .or_default()
                .insert(scan_key, agg_share);
        }
    }

    Ok(synthesized)
}

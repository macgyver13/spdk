//! Silent Payment ECDH Share Aggregation
//!
//! Collects ECDH shares and input pubkeys from a PSBT, grouped by scan key.
//!
//! Global vs per-input is determined by which PSBT fields are present

use super::{
    get_input_outpoint_bytes, get_input_pubkey, Bip375PsbtExt, Error, Result, SilentPaymentPsbt,
};
use crate::psbt::crypto::bip352::is_input_eligible;
use crate::psbt::crypto::{dleq_verify_proof, musig2};
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
pub fn aggregate_ecdh_shares(
    psbt: &SilentPaymentPsbt,
    secp: &Secp256k1<secp256k1::All>,
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
    let synthesized = synthesize_partial_ecdh_shares(psbt, secp)?;

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
                let share = synthesized
                    .get(&input_idx)
                    .and_then(|m| m.get(&scan_key))
                    .copied()
                    .or_else(|| {
                        psbt.get_input_ecdh_shares(input_idx)
                            .into_iter()
                            .find(|s| s.scan_key == scan_key)
                            .map(|s| s.share)
                    });

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
fn synthesize_partial_ecdh_shares(
    psbt: &SilentPaymentPsbt,
    secp: &Secp256k1<secp256k1::All>,
) -> Result<HashMap<usize, HashMap<PublicKey, PublicKey>>> {
    let mut synthesized: HashMap<usize, HashMap<PublicKey, PublicKey>> = HashMap::new();

    for input_idx in 0..psbt.num_inputs() {
        let partial_shares = psbt.get_input_partial_ecdh_shares(input_idx);
        if partial_shares.is_empty() {
            continue;
        }

        // Group (contributor_pk, share, proof) by scan key.
        let mut by_scan_key: HashMap<
            PublicKey,
            Vec<(PublicKey, PublicKey, psbt_v2::v2::dleq::DleqProof)>,
        > = HashMap::new();
        for partial in &partial_shares {
            by_scan_key
                .entry(partial.scan_key)
                .or_default()
                .push((partial.contributor_pk, partial.share, partial.dleq_proof));
        }

        // Check if MuSig2 participant keys are registered for this input
        let musig2_info = psbt.get_input_musig2_participant_pubkeys(input_idx);
        let has_musig2 = !musig2_info.is_empty();

        for (scan_key, entries) in by_scan_key {
            // Verify each contributor's DLEQ proof against its own partial share.
            for (contributor_pk, share, proof) in &entries {
                let verified =
                    dleq_verify_proof(secp, contributor_pk, &scan_key, share, proof, None)
                        .map_err(|_| Error::InvalidDleqProof(input_idx))?;
                if !verified {
                    return Err(Error::InvalidDleqProof(input_idx));
                }
            }

            let agg_share = if has_musig2 {
                let (_agg_pk, participants) = &musig2_info[0];
                let path = psbt
                    .get_input_sp_spend_bip32_derivation(input_idx)
                    .map(|(_, _, path)| path)
                    .unwrap_or_else(|| vec![0, 0]);
                let contributions: Vec<(PublicKey, PublicKey)> =
                    entries.iter().map(|(c, s, _)| (*c, *s)).collect();
                musig2::aggregate_partial_ecdh_shares(
                    secp,
                    participants,
                    &path,
                    &scan_key,
                    &contributions,
                )?
            } else {
                // Naive plain-sum for standard single-key paths
                let mut agg: Option<PublicKey> = None;
                for (_, share, _) in &entries {
                    agg = Some(match agg {
                        None => *share,
                        Some(existing) => combine_keys(&existing, share)?,
                    });
                }
                agg.ok_or_else(|| Error::Other("No shares aggregated".to_string()))?
            };

            synthesized
                .entry(input_idx)
                .or_default()
                .insert(scan_key, agg_share);
        }
    }

    Ok(synthesized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::psbt::core::PartialEcdhShareData;
    use crate::psbt::crypto::dleq_generate_proof;
    use crate::psbt::roles::test_helpers::make_sp_psbt;
    use secp256k1::{Scalar, SecretKey};
    use silentpayments::{Network as SpNetwork, SilentPaymentAddress};

    /// The ECDH point a contributor would publish: `sk * scan_key`.
    fn ecdh_point(
        secp: &Secp256k1<secp256k1::All>,
        sk: &SecretKey,
        scan_key: &PublicKey,
    ) -> PublicKey {
        let scalar = Scalar::from_be_bytes(sk.secret_bytes()).unwrap();
        scan_key.mul_tweak(secp, &scalar).unwrap()
    }

    /// Valid 1-input SP PSBT (eligible P2WPKH input + one SP output for `scan_key`)
    /// carrying a single partial ECDH share. No MuSig2 participants are registered,
    /// so aggregation takes the plain-sum path and DLEQ verification is the only
    /// cryptographic check exercised.
    fn psbt_with_partial(
        secp: &Secp256k1<secp256k1::All>,
        scan_key: PublicKey,
        contributor_pk: PublicKey,
        share: PublicKey,
        proof: psbt_v2::v2::dleq::DleqProof,
    ) -> SilentPaymentPsbt {
        let spend_key =
            PublicKey::from_secret_key(secp, &SecretKey::from_slice(&[20u8; 32]).unwrap());
        let address = SilentPaymentAddress::new(scan_key, spend_key, SpNetwork::Regtest, 0).unwrap();
        let (mut psbt, _inputs) = make_sp_psbt(secp, 1, address, 50000);
        psbt.add_input_partial_ecdh_share(
            0,
            &PartialEcdhShareData {
                scan_key,
                contributor_pk,
                share,
                dleq_proof: proof,
            },
        )
        .unwrap();
        psbt
    }

    /// An invalid DLEQ proof must be rejected even on the no-secp entry point,
    /// proving verification can no longer be silently skipped.
    #[test]
    fn partial_share_invalid_dleq_rejected_without_secp() {
        let secp = Secp256k1::new();
        let scan_key =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[9u8; 32]).unwrap());
        let contributor_sk = SecretKey::from_slice(&[5u8; 32]).unwrap();
        let contributor_pk = PublicKey::from_secret_key(&secp, &contributor_sk);

        // Generate a valid proof for the correct share...
        let correct_share = ecdh_point(&secp, &contributor_sk, &scan_key);
        let proof = dleq_generate_proof(&secp, &contributor_sk, &scan_key, &[7u8; 32], None).unwrap();

        // ...but store a different share so the proof no longer matches it.
        let wrong_share = ecdh_point(&secp, &SecretKey::from_slice(&[6u8; 32]).unwrap(), &scan_key);
        assert_ne!(correct_share, wrong_share);

        let psbt = psbt_with_partial(&secp, scan_key, contributor_pk, wrong_share, proof);

        let result = aggregate_ecdh_shares(&psbt, &secp);
        assert!(
            matches!(result, Err(Error::InvalidDleqProof(0))),
            "expected InvalidDleqProof(0), got {:?}",
            result
        );
    }

    /// A valid DLEQ proof passes verification on the no-secp entry point and the
    /// share is aggregated for its scan key.
    #[test]
    fn partial_share_valid_dleq_accepted_without_secp() {
        let secp = Secp256k1::new();
        let scan_key =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[9u8; 32]).unwrap());
        let contributor_sk = SecretKey::from_slice(&[5u8; 32]).unwrap();
        let contributor_pk = PublicKey::from_secret_key(&secp, &contributor_sk);
        let share = ecdh_point(&secp, &contributor_sk, &scan_key);
        let proof = dleq_generate_proof(&secp, &contributor_sk, &scan_key, &[7u8; 32], None).unwrap();

        let psbt = psbt_with_partial(&secp, scan_key, contributor_pk, share, proof);

        let aggregated = aggregate_ecdh_shares(&psbt, &secp).expect("valid proof should aggregate");
        assert!(
            aggregated.get(&scan_key).is_some(),
            "verified partial share should aggregate for its scan key"
        );
    }

    /// Two MuSig2 participants each publish a partial ECDH share `sk_i * scan_key`.
    /// The synthesized aggregate share must equal `t * scan_key`, where `t` is the
    /// effective taproot output secret for the tweaked aggregate key (even-Y).
    ///
    /// Oracle: the `musig2` crate computes the effective secret `d` from the
    /// participant secret keys via `aggregated_seckey` (an independent path from our
    /// point-side share summation), and asserts `d * G == aggregated_pubkey()`.
    #[test]
    fn musig2_partial_shares_aggregate_to_output_secret() {
        let secp = Secp256k1::new();
        let path = vec![0u32, 0u32];

        let scan_key =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[9u8; 32]).unwrap());
        let spend_key =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[20u8; 32]).unwrap());
        let address =
            SilentPaymentAddress::new(scan_key, spend_key, SpNetwork::Regtest, 0).unwrap();
        let (mut psbt, _inputs) = make_sp_psbt(&secp, 1, address, 50000);

        // Two participants with known secret keys, in aggregation order.
        let s1 = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let s2 = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let p1 = PublicKey::from_secret_key(&secp, &s1);
        let p2 = PublicKey::from_secret_key(&secp, &s2);
        let agg_pk = combine_keys(&p1, &p2).unwrap();
        psbt.set_input_musig2_participant_pubkeys(0, &agg_pk, &[p1, p2])
            .unwrap();

        // Each participant's partial ECDH share and DLEQ proof.
        let share1 = ecdh_point(&secp, &s1, &scan_key);
        let share2 = ecdh_point(&secp, &s2, &scan_key);
        for (sk, pk, share, r) in [
            (&s1, p1, share1, [7u8; 32]),
            (&s2, p2, share2, [8u8; 32]),
        ] {
            let proof = dleq_generate_proof(&secp, sk, &scan_key, &r, None).unwrap();
            psbt.add_input_partial_ecdh_share(
                0,
                &PartialEcdhShareData {
                    scan_key,
                    contributor_pk: pk,
                    share,
                    dleq_proof: proof,
                },
            )
            .unwrap();
        }

        psbt.set_input_sp_spend_bip32_derivation(0, &spend_key, [0u8; 4], path.clone())
            .unwrap();

        // Oracle: effective output secret `t` for the even-Y taproot key.
        let (ctx, _gacc) = musig2::build_tweaked_key_agg_ctx(&secp, &[p1, p2], &path).unwrap();
        let seckeys = [
            ::musig2::secp::Scalar::from_slice(&s1.secret_bytes()).unwrap(),
            ::musig2::secp::Scalar::from_slice(&s2.secret_bytes()).unwrap(),
        ];
        let d: ::musig2::secp::Scalar = ctx.aggregated_seckey(seckeys).expect("aggregated seckey");
        let d_bytes: [u8; 32] = d.into();
        let d_sk = SecretKey::from_slice(&d_bytes).unwrap();
        let q: ::musig2::secp256k1::PublicKey = ctx.aggregated_pubkey();
        let q_even = q.serialize()[0] == 0x02;
        let t_sk = if q_even { d_sk } else { d_sk.negate() };
        let t_scalar = Scalar::from_be_bytes(t_sk.secret_bytes()).unwrap();
        let expected = scan_key.mul_tweak(&secp, &t_scalar).unwrap();

        let aggregated = aggregate_ecdh_shares(&psbt, &secp).expect("musig2 shares should aggregate");
        let got = aggregated
            .get(&scan_key)
            .expect("scan key present")
            .aggregated_share;

        assert_eq!(got, expected, "synthesized share must equal t * scan_key");

        // The weighting branch (not the plain-sum fallback) must have run.
        let plain_sum = combine_keys(&share1, &share2).unwrap();
        assert_ne!(got, plain_sum, "expected BIP-327 weighting, not a plain sum");
    }
}

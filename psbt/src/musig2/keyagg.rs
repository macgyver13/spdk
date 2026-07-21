//! MuSig2 key aggregation (BIP-327) and BIP-328 synthetic derivation.
//!
//! Ported from the old `spdk-core::psbt::crypto::musig2` module (revision
//! `slznmzkv`, `musig2-feature` branch) — the new standalone `psbt` crate dropped
//! this functionality.
//!
//! # Byte Boundary Note
//!
//! The `musig2` crate pins `secp256k1 = "0.31"` while the rest of the workspace
//! uses `secp256k1 = "0.29"`. The types are incompatible at the Rust level, so all
//! key material crosses the version boundary via serialized bytes. The conversion
//! helpers are isolated here.
//! TODO: Remove the conversion shims once the workspace upgrades to secp256k1 0.31+.

use anyhow::{anyhow, Result};
use bitcoin::bip32::{ChildNumber, Xpub};
use hmac::{Hmac, Mac};
use musig2::KeyAggContext;
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use sha2::Sha512;

type HmacSha512 = Hmac<Sha512>;

/// BIP-328 synthetic-account root chaincode for MuSig2 derivation.
const BIP328_SYNTHETIC_CHAINCODE_HEX: &str =
    "868087ca02a6f974c4598924c36b57762d32cb45717167e300622c7167e38965";

// ===== Key Aggregation =====

/// How the per-index aggregate key is produced.
///
/// The two orders are not interchangeable and must not be mixed within one PSBT: a
/// combiner running in the wrong mode for the shares it was given -- treating
/// DeriveThenAggregate shares as AggregateThenDerive, or vice versa -- silently
/// derives the wrong key rather than failing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AggregationMode<'a> {
    /// BIP-328 synthetic derivation. `participants` are account-level keys; the
    /// aggregate is derived along `path` from the synthetic-root chaincode after
    /// aggregation. `xᵢ` stays account-level, so a partial ECDH share for a given
    /// scan key is identical at every derivation index.
    AggregateThenDerive { path: &'a [u32] },
    /// BIP-390 ranged participants. `participants` are already derived for the
    /// target index (e.g. via [`derive_participants`]); no BIP-328 tweaks are
    /// applied. `xᵢ` is a per-index child, so a partial ECDH share for a given scan
    /// key differs at every derivation index.
    DeriveThenAggregate,
}

/// A MuSig2 aggregation context tweaked for a single silent-payment input, together
/// with the BIP-327 parity accumulator needed to combine partial ECDH shares.
pub struct TweakedKeyAgg {
    pub ctx: KeyAggContext,
    /// BIP-327 `gacc`: parity of the aggregate pubkey after any plain tweaks but
    /// before the taproot tweak.
    pub gacc: i8,
}

/// Build a MuSig2 key aggregation context from ordered participant public keys.
///
/// Participants are aggregated in the order given; callers must use a consistent
/// order between signing and share synthesis so both derive the same aggregate key.
pub fn build_key_agg_ctx(participants: &[PublicKey]) -> Result<KeyAggContext> {
    // BIP-327 KeySort: aggregate over participants sorted by their 33-byte
    // compressed serialization. The PSBT stores participant keys in plain order,
    // so the aggregator must sort to reproduce the same aggregate key the wallet
    // committed to.
    let mut sorted = participants.to_vec();
    sorted.sort_by_key(|k| k.serialize());

    let points: Vec<musig2::secp256k1::PublicKey> =
        sorted.iter().map(to_musig2_pubkey).collect::<Result<_>>()?;

    KeyAggContext::new(points).map_err(|e| anyhow!("key aggregation failed: {e}"))
}

/// Derive each participant xpub along `path`, returning keys ready for
/// [`AggregationMode::DeriveThenAggregate`].
///
/// Ordinary (unhardened) BIP-32 derivation only: `path` entries must be within
/// `[0, 2^31 - 1]`, matching BIP-390's restriction that `musig()` participants with
/// derivation steps cannot be hardened. `Xpub::ckd_pub` independently rejects a
/// hardened step, so a violation surfaces as an error rather than silently deriving
/// the wrong key.
///
/// Does not sort the result -- [`build_key_agg_ctx`] performs BIP-327 KeySort
/// internally, and sorting here as well would risk the two sort sites drifting apart.
pub fn derive_participants(
    secp: &Secp256k1<secp256k1::All>,
    participants: &[Xpub],
    path: &[u32],
) -> Result<Vec<PublicKey>> {
    let child_path: Vec<ChildNumber> = path
        .iter()
        .map(|&index| {
            ChildNumber::from_normal_idx(index)
                .map_err(|e| anyhow!("invalid unhardened path index {index}: {e}"))
        })
        .collect::<Result<_>>()?;

    participants
        .iter()
        .map(|xpub| {
            xpub.derive_pub(secp, &child_path)
                .map(|derived| derived.public_key)
                .map_err(|e| anyhow!("participant derivation failed: {e}"))
        })
        .collect()
}

/// Build the fully tweaked aggregation context for a silent-payment MuSig2 input.
///
/// Under [`AggregationMode::AggregateThenDerive`], applies the BIP-328 plain tweaks
/// derived from `path` before the taproot tweak. Under
/// [`AggregationMode::DeriveThenAggregate`], `participants` are assumed already
/// derived for the target index and no plain tweaks are applied -- the returned
/// `gacc` is then simply the parity of the bare aggregate.
///
/// Either way, the taproot tweak is always applied, and the returned `gacc` is the
/// parity of the aggregate pubkey after any plain tweaks but before the taproot
/// tweak -- the accumulator BIP-327 `Sign` and this module's ECDH-share aggregation
/// both expect.
pub fn build_tweaked_key_agg_ctx(
    secp: &Secp256k1<secp256k1::All>,
    participants: &[PublicKey],
    mode: AggregationMode<'_>,
) -> Result<TweakedKeyAgg> {
    let mut ctx = build_key_agg_ctx(participants)?;

    if let AggregationMode::AggregateThenDerive { path } = mode {
        // Apply BIP-328 plain tweaks derived from the synthetic root and PSBT path.
        let base_pk = from_musig2_pubkey(&ctx.aggregated_pubkey())?;
        for tweak in derive_bip328_plain_tweaks(secp, &base_pk, path)? {
            let musig_scalar = musig2::secp256k1::Scalar::from_be_bytes(tweak)
                .map_err(|e| anyhow!("invalid musig tweak scalar: {e}"))?;
            ctx = ctx
                .with_plain_tweak(musig_scalar)
                .map_err(|e| anyhow!("plain tweak failed: {e}"))?;
        }
    }

    let gacc = pubkey_parity(&from_musig2_pubkey(&ctx.aggregated_pubkey())?);

    let ctx = ctx
        .with_unspendable_taproot_tweak()
        .map_err(|e| anyhow!("taproot tweak failed: {e}"))?;

    Ok(TweakedKeyAgg { ctx, gacc })
}

// ===== Partial ECDH Share Aggregation (BIP-327) =====

/// Combine per-participant ECDH shares into the aggregate-key ECDH share.
///
/// Each contributor's share is weighted by its BIP-327 key coefficient, the sum is
/// adjusted for the aggregate-key parity, and the accumulated tweak term
/// `(g2 * tacc) * scan_key` is added. `participants` and `mode` must match what the
/// contributors used to compute their individual shares -- see
/// [`AggregationMode`]. `contributions` is the `(contributor_pubkey, partial_share)`
/// pairs for the given `scan_key`.
pub fn aggregate_partial_ecdh_shares(
    secp: &Secp256k1<secp256k1::All>,
    participants: &[PublicKey],
    mode: AggregationMode<'_>,
    scan_key: &PublicKey,
    contributions: &[(PublicKey, PublicKey)],
) -> Result<PublicKey> {
    if contributions.is_empty() {
        return Err(anyhow!("no partial shares to aggregate"));
    }

    let agg = build_tweaked_key_agg_ctx(secp, participants, mode)?;
    aggregate_shares_with_ctx(secp, &agg, scan_key, contributions)
}

/// Shared core of [`aggregate_partial_ecdh_shares`]: given an already-tweaked
/// aggregation context, weight and combine the partial shares. Mode-independent --
/// [`build_tweaked_key_agg_ctx`] is the only place the two orders diverge.
fn aggregate_shares_with_ctx(
    secp: &Secp256k1<secp256k1::All>,
    agg: &TweakedKeyAgg,
    scan_key: &PublicKey,
    contributions: &[(PublicKey, PublicKey)],
) -> Result<PublicKey> {
    let TweakedKeyAgg { ctx, gacc } = agg;

    // Parity after the taproot tweak (g2), combined with the pre-taproot parity (gacc).
    let g2 = pubkey_parity(&from_musig2_pubkey(&ctx.aggregated_pubkey())?);
    let c = g2 * gacc;

    let tacc_bytes: [u8; 32] = match ctx.tweak_sum::<musig2::secp::Scalar>() {
        Some(t) => t.into(),
        None => [0u8; 32],
    };

    // Weight each contributor's share by its key coefficient and sum the terms.
    let mut sum: Option<PublicKey> = None;
    for (contributor_pk, share) in contributions {
        let coeff = key_coefficient(ctx, contributor_pk)?;
        let term = share.mul_tweak(secp, &coeff)?;
        sum = Some(match sum {
            None => term,
            Some(acc) => acc.combine(&term)?,
        });
    }
    let sum = sum.expect("contributions checked non-empty");

    // Apply the parity adjustment c = g2 * gacc.
    let sum_c = if c == 1 { sum } else { negate_pubkey(sum) };

    // Add the (g2 * tacc) * scan_key term when a tweak has accumulated.
    if tacc_bytes == [0u8; 32] {
        return Ok(sum_c);
    }

    let g2_tacc = {
        let sk = SecretKey::from_slice(&tacc_bytes)?;
        if g2 == -1 {
            sk.negate()
        } else {
            sk
        }
    };
    let g2_tacc_scalar = Scalar::from_be_bytes(g2_tacc.secret_bytes())
        .map_err(|e| anyhow!("invalid tacc scalar: {e}"))?;
    let tacc_term = scan_key.mul_tweak(secp, &g2_tacc_scalar)?;

    Ok(sum_c.combine(&tacc_term)?)
}

// ===== Internal Helpers =====

/// Derive BIP-328 plain tweaks by walking `path` from the synthetic-root chaincode.
fn derive_bip328_plain_tweaks(
    secp: &Secp256k1<secp256k1::All>,
    base_pk: &PublicKey,
    path: &[u32],
) -> Result<Vec<[u8; 32]>> {
    let mut chaincode = hex::decode(BIP328_SYNTHETIC_CHAINCODE_HEX)
        .map_err(|e| anyhow!("invalid synthetic chaincode: {e}"))?;
    let mut current_pk = *base_pk;
    let mut tweaks = Vec::with_capacity(path.len());

    for index in path {
        let mut data = Vec::with_capacity(37);
        data.extend_from_slice(&current_pk.serialize());
        data.extend_from_slice(&index.to_be_bytes());

        let mut mac =
            HmacSha512::new_from_slice(&chaincode).map_err(|e| anyhow!("HMAC init failed: {e}"))?;
        mac.update(&data);
        let result = mac.finalize().into_bytes();

        let il: [u8; 32] = result[0..32].try_into().expect("slice is 32 bytes");
        let ir: [u8; 32] = result[32..64].try_into().expect("slice is 32 bytes");

        let scalar =
            Scalar::from_be_bytes(il).map_err(|e| anyhow!("invalid derivation scalar: {e}"))?;
        current_pk = current_pk.add_exp_tweak(secp, &scalar)?;

        tweaks.push(il);
        chaincode = ir.to_vec();
    }

    Ok(tweaks)
}

/// BIP-327 key coefficient for `contributor`, as a workspace (0.29) scalar.
fn key_coefficient(ctx: &KeyAggContext, contributor: &PublicKey) -> Result<Scalar> {
    let musig_contributor = to_musig2_pubkey(contributor)?;
    let coeff = ctx
        .key_coefficient(musig_contributor)
        .ok_or_else(|| anyhow!("missing key coefficient for contributor"))?;

    let coeff_bytes: [u8; 32] = match coeff {
        musig2::secp::MaybeScalar::Valid(scalar) => scalar.into(),
        musig2::secp::MaybeScalar::Zero => [0u8; 32],
    };
    Scalar::from_be_bytes(coeff_bytes).map_err(|e| anyhow!("invalid coefficient scalar: {e}"))
}

/// Parity sign of a public key: +1 for an even Y, -1 for an odd Y.
fn pubkey_parity(pk: &PublicKey) -> i8 {
    if pk.serialize()[0] == 0x02 {
        1
    } else {
        -1
    }
}

/// Negate a public key by flipping its parity byte.
fn negate_pubkey(pk: PublicKey) -> PublicKey {
    let mut bytes = pk.serialize();
    bytes[0] = if bytes[0] == 0x02 { 0x03 } else { 0x02 };
    PublicKey::from_slice(&bytes).expect("flipping parity yields a valid point")
}

// ===== Byte-Boundary Conversions (secp256k1 0.29 <-> musig2 0.31) =====

pub fn to_musig2_pubkey(pk: &PublicKey) -> Result<musig2::secp256k1::PublicKey> {
    musig2::secp256k1::PublicKey::from_slice(&pk.serialize())
        .map_err(|e| anyhow!("pubkey 0.29->0.31 conversion failed: {e}"))
}

pub fn from_musig2_pubkey(pk: &musig2::secp256k1::PublicKey) -> Result<PublicKey> {
    PublicKey::from_slice(&pk.serialize()).map_err(|e| anyhow!("pubkey 0.31->0.29: {e}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use bitcoin::bip32::Xpriv;
    use bitcoin::NetworkKind;
    use secp256k1::SecretKey;

    /// Master keys for two participants, derived from fixed seeds so the test is
    /// deterministic without depending on a mnemonic wordlist.
    fn participant_masters() -> (Xpriv, Xpriv) {
        let m1 = Xpriv::new_master(NetworkKind::Test, &[0x11; 32]).unwrap();
        let m2 = Xpriv::new_master(NetworkKind::Test, &[0x22; 32]).unwrap();
        (m1, m2)
    }

    /// Unhardened BIP-32 path, for `Xpriv::derive_priv` / `Xpub::derive_pub`, which
    /// take `ChildNumber` rather than raw indices.
    fn unhardened_path(indices: &[u32]) -> Vec<ChildNumber> {
        indices
            .iter()
            .map(|&i| ChildNumber::from_normal_idx(i).unwrap())
            .collect()
    }

    /// The ECDH point a contributor publishes: `sk * scan_key`.
    fn ecdh_point(
        secp: &Secp256k1<secp256k1::All>,
        sk: &SecretKey,
        scan_key: &PublicKey,
    ) -> PublicKey {
        let scalar = Scalar::from_be_bytes(sk.secret_bytes()).unwrap();
        scan_key.mul_tweak(secp, &scalar).unwrap()
    }

    /// Two MuSig2 participants each publish `sk_i * scan_key`; the synthesized
    /// aggregate share must equal `t * scan_key`, where `t` is the effective
    /// taproot output secret for the tweaked aggregate key (even-Y).
    ///
    /// Oracle: `musig2::aggregated_seckey` computes `t` from the participant secret
    /// keys via an independent (scalar-side) path from our point-side summation.
    #[test]
    fn musig2_participant_shares_aggregate_to_output_secret() {
        let secp = Secp256k1::new();
        let path = vec![0u32, 0u32];

        let scan_key =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[9u8; 32]).unwrap());
        let s1 = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let s2 = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let p1 = PublicKey::from_secret_key(&secp, &s1);
        let p2 = PublicKey::from_secret_key(&secp, &s2);
        let share1 = ecdh_point(&secp, &s1, &scan_key);
        let share2 = ecdh_point(&secp, &s2, &scan_key);

        // Oracle: effective output secret `t` for the even-Y taproot key. The ctx
        // applies BIP-327 KeySort, so the seckeys handed to `aggregated_seckey` must
        // be ordered the same way (by compressed pubkey).
        let agg = build_tweaked_key_agg_ctx(
            &secp,
            &[p1, p2],
            AggregationMode::AggregateThenDerive { path: &path },
        )
        .unwrap();
        let ctx = &agg.ctx;
        let mut pairs = [(s1, p1), (s2, p2)];
        pairs.sort_by(|a, b| a.1.serialize().cmp(&b.1.serialize()));
        let seckeys = [
            musig2::secp::Scalar::from_slice(&pairs[0].0.secret_bytes()).unwrap(),
            musig2::secp::Scalar::from_slice(&pairs[1].0.secret_bytes()).unwrap(),
        ];
        let d: musig2::secp::Scalar = ctx.aggregated_seckey(seckeys).unwrap();
        let d_bytes: [u8; 32] = d.into();
        let d_sk = SecretKey::from_slice(&d_bytes).unwrap();
        let q: musig2::secp256k1::PublicKey = ctx.aggregated_pubkey();
        let q_even = q.serialize()[0] == 0x02;
        let t_sk = if q_even { d_sk } else { d_sk.negate() };
        let t_scalar = Scalar::from_be_bytes(t_sk.secret_bytes()).unwrap();
        let expected = scan_key.mul_tweak(&secp, &t_scalar).unwrap();

        let got = aggregate_partial_ecdh_shares(
            &secp,
            &[p1, p2],
            AggregationMode::AggregateThenDerive { path: &path },
            &scan_key,
            &[(p1, share1), (p2, share2)],
        )
        .unwrap();

        assert_eq!(got, expected, "synthesized share must equal t * scan_key");

        let plain_sum = share1.combine(&share2).unwrap();
        assert_ne!(
            got, plain_sum,
            "expected BIP-327 weighting, not a plain sum"
        );
    }

    /// Mirror of `musig2_participant_shares_aggregate_to_output_secret` above, but
    /// with participants derived first (BIP-390 ranged participants /
    /// DeriveThenAggregate) instead of account-level keys tweaked after aggregation
    /// (BIP-328 synthetic derivation / AggregateThenDerive). Same independent
    /// scalar-side oracle. This is the "does the theory hold" check: it establishes
    /// that DeriveThenAggregate is not just a different code path but a correct one.
    #[test]
    fn derive_then_aggregate_shares_aggregate_to_output_secret() {
        let secp = Secp256k1::new();
        let path = unhardened_path(&[0, 3]);
        let (m1, m2) = participant_masters();
        let c1 = m1.derive_priv(&secp, &path).unwrap();
        let c2 = m2.derive_priv(&secp, &path).unwrap();

        let scan_key =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[9u8; 32]).unwrap());
        let s1 = c1.private_key;
        let s2 = c2.private_key;
        let p1 = PublicKey::from_secret_key(&secp, &s1);
        let p2 = PublicKey::from_secret_key(&secp, &s2);
        let share1 = ecdh_point(&secp, &s1, &scan_key);
        let share2 = ecdh_point(&secp, &s2, &scan_key);

        // Oracle: same construction as the AggregateThenDerive test above, but with
        // no plain tweaks -- DeriveThenAggregate applies the taproot tweak only.
        let agg =
            build_tweaked_key_agg_ctx(&secp, &[p1, p2], AggregationMode::DeriveThenAggregate)
                .unwrap();
        let ctx = &agg.ctx;
        let mut pairs = [(s1, p1), (s2, p2)];
        pairs.sort_by(|a, b| a.1.serialize().cmp(&b.1.serialize()));
        let seckeys = [
            musig2::secp::Scalar::from_slice(&pairs[0].0.secret_bytes()).unwrap(),
            musig2::secp::Scalar::from_slice(&pairs[1].0.secret_bytes()).unwrap(),
        ];
        let d: musig2::secp::Scalar = ctx.aggregated_seckey(seckeys).unwrap();
        let d_bytes: [u8; 32] = d.into();
        let d_sk = SecretKey::from_slice(&d_bytes).unwrap();
        let q: musig2::secp256k1::PublicKey = ctx.aggregated_pubkey();
        let q_even = q.serialize()[0] == 0x02;
        let t_sk = if q_even { d_sk } else { d_sk.negate() };
        let t_scalar = Scalar::from_be_bytes(t_sk.secret_bytes()).unwrap();
        let expected = scan_key.mul_tweak(&secp, &t_scalar).unwrap();

        let got = aggregate_partial_ecdh_shares(
            &secp,
            &[p1, p2],
            AggregationMode::DeriveThenAggregate,
            &scan_key,
            &[(p1, share1), (p2, share2)],
        )
        .unwrap();

        assert_eq!(got, expected, "synthesized share must equal t * scan_key");

        let plain_sum = share1.combine(&share2).unwrap();
        assert_ne!(
            got, plain_sum,
            "expected BIP-327 weighting, not a plain sum"
        );
    }

    /// The two orders must not silently collapse into each other: aggregating
    /// account-level participants (AggregateThenDerive) and aggregating the same
    /// participants pre-derived at an index (DeriveThenAggregate) must produce
    /// different aggregate keys -- they are different wallets, and a combiner that
    /// confused the two would derive the wrong key with no error. Also exercises
    /// `derive_participants` against the same derivation done manually on the
    /// private side, as a cross-check that the two agree.
    #[test]
    fn orders_produce_different_aggregate_keys() {
        let secp = Secp256k1::new();
        let path_u32 = [0u32, 2u32];
        let path_cn = unhardened_path(&path_u32);
        let (m1, m2) = participant_masters();

        let account_pk1 = PublicKey::from_secret_key(&secp, &m1.private_key);
        let account_pk2 = PublicKey::from_secret_key(&secp, &m2.private_key);
        let agg_then_derive = build_tweaked_key_agg_ctx(
            &secp,
            &[account_pk1, account_pk2],
            AggregationMode::AggregateThenDerive { path: &path_u32 },
        )
        .unwrap();

        // Manual private-side derivation, for comparison against derive_participants.
        let manual_p1 = PublicKey::from_secret_key(
            &secp,
            &m1.derive_priv(&secp, &path_cn).unwrap().private_key,
        );
        let manual_p2 = PublicKey::from_secret_key(
            &secp,
            &m2.derive_priv(&secp, &path_cn).unwrap().private_key,
        );

        // derive_participants operates on public xpubs, as a verifier without
        // private keys would use it.
        let xpub1 = Xpub::from_priv(&secp, &m1);
        let xpub2 = Xpub::from_priv(&secp, &m2);
        let derived = derive_participants(&secp, &[xpub1, xpub2], &path_u32).unwrap();
        assert_eq!(
            derived,
            vec![manual_p1, manual_p2],
            "derive_participants must agree with private-side derivation"
        );

        let derive_then_agg =
            build_tweaked_key_agg_ctx(&secp, &derived, AggregationMode::DeriveThenAggregate)
                .unwrap();

        let q_synthetic = from_musig2_pubkey(&agg_then_derive.ctx.aggregated_pubkey()).unwrap();
        let q_derived = from_musig2_pubkey(&derive_then_agg.ctx.aggregated_pubkey()).unwrap();
        assert_ne!(
            q_synthetic, q_derived,
            "the two key orders must produce different aggregate keys -- they are different wallets"
        );
    }

    /// The privacy claim, reduced to two assertions. Under AggregateThenDerive the
    /// raw share `x_i * B_scan` never consumes the address index at all -- there is
    /// no path parameter in the computation -- so it is a stable `(wallet,
    /// recipient)` identifier across every payroll. Under DeriveThenAggregate `x_i`
    /// is a per-index child of the participant's xpriv, so the share differs at
    /// every index.
    #[test]
    fn shares_rotate_under_derive_then_aggregate_only() {
        let secp = Secp256k1::new();
        let (m1, _m2) = participant_masters();
        let scan_key =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[9u8; 32]).unwrap());
        let path_index_0 = unhardened_path(&[0, 0]);
        let path_index_1 = unhardened_path(&[0, 1]);

        // AggregateThenDerive: the raw share is x_i * B_scan for the account-level
        // secret x_i, which has no dependence on the address index -- both
        // "indices" below are the same share by construction. The assertion
        // documents that, rather than testing anything that could fail.
        let account_secret = m1.private_key;
        let share_at_index_0 = ecdh_point(&secp, &account_secret, &scan_key);
        let share_at_index_1 = ecdh_point(&secp, &account_secret, &scan_key);
        assert_eq!(
            share_at_index_0, share_at_index_1,
            "AggregateThenDerive: share is a stable (wallet, recipient) identifier"
        );

        // DeriveThenAggregate: x_i is a per-index child of the participant's xpriv,
        // so the raw share differs at every index.
        let child_at_index_0 = m1.derive_priv(&secp, &path_index_0).unwrap();
        let child_at_index_1 = m1.derive_priv(&secp, &path_index_1).unwrap();
        let derived_share_at_index_0 =
            ecdh_point(&secp, &child_at_index_0.private_key, &scan_key);
        let derived_share_at_index_1 =
            ecdh_point(&secp, &child_at_index_1.private_key, &scan_key);
        assert_ne!(
            derived_share_at_index_0, derived_share_at_index_1,
            "DeriveThenAggregate: share rotates with the address index"
        );
    }
}

/// Test helpers for setting up properly configured PSBTs in role tests.
///
/// P2WPKH inputs require witness_utxo (via add_inputs) and bip32_derivations
/// (via the updater role) for is_input_eligible and get_input_pubkey to work.
/// These helpers encapsulate that setup so individual tests stay focused.

use crate::psbt::core::{PsbtInput, PsbtOutput, SilentPaymentPsbt};
use crate::psbt::crypto::pubkey_to_p2wpkh_script;
use crate::psbt::roles::{
    constructor::{add_inputs, add_outputs},
    creator::create_psbt,
    updater::{add_input_bip32_derivation, Bip32Derivation},
};
use bitcoin::hashes::Hash;
use bitcoin::{Amount, OutPoint, Sequence, TxOut, Txid};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use silentpayments::SilentPaymentAddress;

/// Build a PSBT with `n` P2WPKH inputs (privkeys `[seed; 32]` for `seed` in `1..=n`).
/// Sets witness_utxo and bip32_derivations on each input. 1 empty output slot.
pub(super) fn make_p2wpkh_psbt(
    secp: &Secp256k1<secp256k1::All>,
    n_inputs: usize,
) -> (SilentPaymentPsbt, Vec<PsbtInput>) {
    let mut psbt = create_psbt(n_inputs, 1);
    let (inputs, pubkeys) = p2wpkh_inputs(secp, n_inputs);
    add_inputs(&mut psbt, &inputs).unwrap();
    register_bip32(&mut psbt, &pubkeys);
    (psbt, inputs)
}

/// Build a PSBT with `n` P2WPKH inputs and one silent payment output.
pub(super) fn make_sp_psbt(
    secp: &Secp256k1<secp256k1::All>,
    n_inputs: usize,
    sp_address: SilentPaymentAddress,
    output_amount: u64,
) -> (SilentPaymentPsbt, Vec<PsbtInput>) {
    let mut psbt = create_psbt(n_inputs, 1);
    let (inputs, pubkeys) = p2wpkh_inputs(secp, n_inputs);
    add_inputs(&mut psbt, &inputs).unwrap();
    add_outputs(
        &mut psbt,
        &[PsbtOutput::silent_payment(
            Amount::from_sat(output_amount),
            sp_address,
            None,
        )],
    )
    .unwrap();
    register_bip32(&mut psbt, &pubkeys);
    (psbt, inputs)
}

fn p2wpkh_inputs(
    secp: &Secp256k1<secp256k1::All>,
    n: usize,
) -> (Vec<PsbtInput>, Vec<PublicKey>) {
    let inputs: Vec<PsbtInput> = (1..=n)
        .map(|i| {
            let privkey = SecretKey::from_slice(&[i as u8; 32]).unwrap();
            let pubkey = PublicKey::from_secret_key(secp, &privkey);
            PsbtInput::new(
                OutPoint::new(Txid::all_zeros(), (i - 1) as u32),
                TxOut {
                    value: Amount::from_sat(50000),
                    script_pubkey: pubkey_to_p2wpkh_script(&pubkey),
                },
                Sequence::MAX,
                Some(privkey),
            )
        })
        .collect();
    let pubkeys = inputs
        .iter()
        .map(|inp| PublicKey::from_secret_key(secp, inp.private_key.as_ref().unwrap()))
        .collect();
    (inputs, pubkeys)
}

fn register_bip32(psbt: &mut SilentPaymentPsbt, pubkeys: &[PublicKey]) {
    let derivation = Bip32Derivation::new([0u8; 4], vec![]);
    for (i, pubkey) in pubkeys.iter().enumerate() {
        add_input_bip32_derivation(psbt, i, pubkey, &derivation).unwrap();
    }
}

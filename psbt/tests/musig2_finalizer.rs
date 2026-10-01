//! MuSig2 silent payment output finalization, against a PSBT two Jade emulators signed on
//! signet: derive-then-aggregate, two silent payment recipients plus change.

use bitcoin::ScriptBuf;
use psbt::musig2::finalize_sp_outputs;
use psbt_v2::Psbt;
use secp256k1::Secp256k1;

const SIGNED: &[u8] = include_bytes!("data/musig2_derive_first_signet.psbt");

fn signed_psbt() -> Psbt {
    Psbt::deserialize(SIGNED).expect("fixture parses")
}

fn scripts(psbt: &Psbt) -> Vec<ScriptBuf> {
    psbt.outputs.iter().map(|output| output.script_pubkey.clone()).collect()
}

fn sp_output_indices(psbt: &Psbt) -> Vec<usize> {
    let indices: Vec<usize> = psbt
        .outputs
        .iter()
        .enumerate()
        .filter(|(_, output)| output.sp_v0_info.is_some())
        .map(|(index, _)| index)
        .collect();
    assert!(!indices.is_empty(), "fixture has silent payment outputs");
    indices
}

#[test]
fn accepts_the_scripts_the_signers_committed_to() {
    let secp = Secp256k1::new();
    let mut psbt = signed_psbt();
    let signed = scripts(&psbt);

    finalize_sp_outputs(&secp, &mut psbt).expect("derived scripts match the signed ones");

    assert_eq!(scripts(&psbt), signed);
}

#[test]
fn rejects_a_tampered_sp_output_script() {
    let secp = Secp256k1::new();
    for index in sp_output_indices(&signed_psbt()) {
        let mut psbt = signed_psbt();
        let mut bytes = psbt.outputs[index].script_pubkey.to_bytes();
        *bytes.last_mut().expect("non-empty script") ^= 1;
        psbt.outputs[index].script_pubkey = ScriptBuf::from_bytes(bytes);

        let error = finalize_sp_outputs(&secp, &mut psbt).expect_err("tampered script must fail");

        assert!(
            error.to_string().contains(&format!("output {index} script does not match")),
            "unexpected error: {error}"
        );
    }
}

#[test]
fn fills_unresolved_sp_output_scripts() {
    let secp = Secp256k1::new();
    let mut psbt = signed_psbt();
    let signed = scripts(&psbt);
    for index in sp_output_indices(&psbt) {
        psbt.outputs[index].script_pubkey = ScriptBuf::new();
    }

    finalize_sp_outputs(&secp, &mut psbt).expect("unresolved scripts are derived");

    assert_eq!(scripts(&psbt), signed);
}

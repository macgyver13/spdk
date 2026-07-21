use bitcoin::CompressedPublicKey;
use psbt_v2::SpV0Info;
use silentpayments::{SilentPaymentAddress, SpVersion, SILENT_PAYMENT_ADDRESS_BYTE_LEN};

pub fn to_rust_dleq(p: psbt_v2::dleq::DleqProof) -> rust_dleq::DleqProof {
    rust_dleq::DleqProof(p.0)
}

pub fn to_psbt_dleq(p: rust_dleq::DleqProof) -> psbt_v2::dleq::DleqProof {
    psbt_v2::dleq::DleqProof(p.0)
}

/// Widens a BIP-375 `PSBT_OUT_SP_V0_INFO` field into the 67-byte BIP-352 address form.
///
/// The PSBT field carries only `scan_key || spend_key`. The leading version byte is an address
/// encoding concern that the field does not carry, and is v0 by definition of the field. The
/// network is not part of the byte form at all.
pub fn to_sp_address_bytes(info: &SpV0Info) -> [u8; SILENT_PAYMENT_ADDRESS_BYTE_LEN] {
    let mut bytes = [0u8; SILENT_PAYMENT_ADDRESS_BYTE_LEN];
    bytes[0] = SpVersion::ZERO.into();
    bytes[1..].copy_from_slice(info.as_bytes());
    bytes
}

/// Builds the BIP-375 `PSBT_OUT_SP_V0_INFO` field for a silent payment address.
///
/// The inverse of [`to_sp_address_bytes`]. The field carries `scan_key || spend_key`; the
/// address version and network are dropped, because the field does not carry them.
pub fn to_sp_v0_info(address: &SilentPaymentAddress) -> SpV0Info {
    SpV0Info::new(
        CompressedPublicKey(address.get_scan_key()),
        CompressedPublicKey(address.get_spend_key()),
    )
}

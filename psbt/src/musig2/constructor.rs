use anyhow::Result;
use bitcoin::OutPoint;
use crate::roles::ConstructorPsbtExt;
use crate::Psbt;
use psbt_v2::Output;

pub fn build_psbt(outpoints: Vec<OutPoint>, outputs: Vec<Output>) -> Result<Psbt> {
    let psbt = Psbt::create_new_transaction(outputs).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let psbt = psbt
        .add_inputs(outpoints)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    Ok(psbt)
}

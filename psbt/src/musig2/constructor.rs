use anyhow::Result;
use bitcoin::OutPoint;
use psbt_v2::{Creator, Input, Output, Psbt};
use rand::seq::SliceRandom;

pub fn build_psbt(outpoints: Vec<OutPoint>, mut outputs: Vec<Output>) -> Result<Psbt> {
    // Randomize the order of the outputs
    outputs.shuffle(&mut rand::thread_rng());

    let mut constructor = Creator::new().constructor_modifiable();
    for output in outputs {
        constructor = constructor
            .output(output)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    }
    for outpoint in outpoints {
        constructor = constructor.input(Input::new(&outpoint));
    }

    Ok(constructor.psbt()?)
}

use serde::{Deserialize, Serialize};

use crate::imt::mutate::IMTMutate;

use super::record_proof::RecordProof;

#[derive(Debug, Deserialize, Serialize)]
pub struct Tx {
    pub record_proof: RecordProof,
    pub imt_mutate: IMTMutate,
}

impl Tx {
    pub fn apply(&self) -> Option<[u8; 32]> {
        // Verify record proof.
        self.record_proof.verify();

        // Verify IMT mutate.
        // TODO: The IMT mutation should only be applied if the provided
        // record proof is up to date with the curremt IMT state.
        let new_root = self.imt_mutate.apply()?;

        // TODO: Verify tx hash.

        Some(new_root)
    }
}

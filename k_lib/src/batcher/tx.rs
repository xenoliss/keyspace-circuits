use serde::{Deserialize, Serialize};

use crate::imt::mutate::IMTMutate;

use super::record_proof::RecordProof;

#[derive(Debug, Deserialize, Serialize)]
pub struct Tx {
    record_proof: RecordProof,
    imt_mutate: IMTMutate,
}

impl Tx {
    pub fn apply(&self) -> Option<[u8; 32]> {
        // Verify record proof.
        self.record_proof.verify();

        // Verify IMT mutate.
        let new_root = self.imt_mutate.apply()?;

        // Verify tx hash.

        Some(new_root)
    }
}

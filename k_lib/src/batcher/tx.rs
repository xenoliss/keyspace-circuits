use serde::{Deserialize, Serialize};

use crate::imt::mutate::IMTMutate;

use super::record_proof::RecordProof;

#[derive(Debug, Deserialize, Serialize)]
pub struct Tx {
    pub record_proof: RecordProof,
    pub imt_mutate: IMTMutate,
}

impl Tx {
    pub fn apply(&self, root: [u8; 32]) -> [u8; 32] {
        // TODO: Verify tx hash.

        // If the record proof does not match with the IMTMutate, do not apply the IMTMutate.
        if !self.imt_mutate.is_bound_to_proof(&self.record_proof) {
            return root;
        }

        // Apply the IMTMutate and returned the new root.
        self.imt_mutate.apply(root)
    }
}

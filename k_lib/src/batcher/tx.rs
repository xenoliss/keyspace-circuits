use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::imt::mutate::IMTMutate;

use super::account_proof::AccountProof;

#[derive(Debug, Deserialize, Serialize)]
pub struct Tx {
    account_proof: AccountProof,
    imt_mutate: IMTMutate,
}

impl Tx {
    pub fn verify(&self, old_root: &[u8; 32]) -> Result<()> {
        // Verify account proof.

        // Verify IMT insert.

        // Verify tx hash.

        Ok(())
    }

    pub fn apply(&self) -> [u8; 32] {
        // Apply IMT insert.
        todo!()
    }
}

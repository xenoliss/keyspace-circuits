use imt::circuits::mutate::IMTMutate;
use serde::{Deserialize, Serialize};

use crate::Hash;

#[derive(Debug, Deserialize, Serialize)]
pub struct PLONKProof {
    /// The record verifier key hash.
    pub record_vk_hash: [u8; 32],
    /// The record proof data.
    pub data: Vec<u8>,
}

impl PLONKProof {
    pub fn is_valid_record_proof(&self, imt_mutate: &IMTMutate<Hash, Hash>) -> bool {
        let (keyspace_id, current_key, new_key) = match imt_mutate {
            IMTMutate::Insert(insert) => (insert.node.key, insert.node.key, insert.node.value),
            IMTMutate::Update(update) => (update.node.key, update.node.value, update.new_value),
        };

        // TODO: Ensure the provided `record_vk_hash` matches with the `current_key`.
        //
        // This check is CRITICAL to ensure that the provided `record_vk_hash` is indeed the one
        // that has control over the KeySpace id. Without this check a malicious user could provide
        // an arbitrary `record_vk_hash` and update any KeySpace record.

        // TODO: Verify the PLONK proof
        true
    }
}

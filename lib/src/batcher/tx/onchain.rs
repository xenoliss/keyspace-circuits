use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Keccak};

use crate::batcher::imt::mutate::IMTMutate;

#[derive(Debug, Deserialize, Serialize)]
pub struct OnchainTx {
    /// The IMT mutate associated with this transaction.
    pub imt_mutate: IMTMutate,
    /// The previous transaction hash (32 bytes).
    pub prev_tx_hash: [u8; 32],
    /// The record verifier key hash.
    pub record_vk_hash: [u8; 32],
    /// The record proof.
    pub record_proof: Vec<u8>,
}

impl OnchainTx {
    pub fn hash(&self) -> [u8; 32] {
        let (keyspace_id, new_key) = match &self.imt_mutate {
            IMTMutate::Insert(insert) => (insert.node.key, insert.node.value_hash),
            IMTMutate::Update(update) => (update.node.key, update.new_value_hash),
        };

        let mut k = Keccak::v256();
        k.update(&self.prev_tx_hash);
        k.update(&keyspace_id);
        k.update(&new_key);
        k.update(&self.record_proof);

        let mut hash = [0; 32];
        k.finalize(&mut hash);
        hash
    }

    pub fn is_valid_record_proof(&self) -> bool {
        let (keyspace_id, current_key, new_key) = match &self.imt_mutate {
            IMTMutate::Insert(insert) => (insert.node.key, insert.node.key, insert.node.value_hash),
            IMTMutate::Update(update) => (
                update.node.key,
                update.node.value_hash,
                update.new_value_hash,
            ),
        };

        // TODO: Verify the PLONK proof
        true
    }

    pub fn apply_imt_mutate(&self, root: &[u8; 32]) -> [u8; 32] {
        self.imt_mutate.apply(*root)
    }
}

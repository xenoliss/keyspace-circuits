use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Keccak};

use crate::batcher::{imt::mutate::IMTMutate, proof::plonk::PLONKProof};

#[derive(Debug, Deserialize, Serialize)]
pub struct OnchainTx {
    /// The IMT mutate associated with this transaction.
    pub imt_mutate: IMTMutate,
    /// The previous transaction hash (32 bytes).
    pub prev_tx_hash: [u8; 32],
    // The PLONK proof to verify.
    pub proof: PLONKProof,
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
        k.update(&self.proof.data);

        let mut hash = [0; 32];
        k.finalize(&mut hash);
        hash
    }

    pub fn is_valid_record_proof(&self) -> bool {
        self.proof.is_valid_record_proof(&self.imt_mutate)
    }
}

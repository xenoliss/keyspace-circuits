use imt::circuits::mutate::IMTMutate;
use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Keccak};

use crate::{batcher::proof::plonk::PLONKProof, Hash};

#[derive(Debug, Deserialize, Serialize)]
pub struct OnchainTx {
    /// The IMT mutate associated with this transaction.
    pub imt_mutate: IMTMutate<Hash, Hash>,
    /// The previous transaction hash.
    pub prev_tx_hash: Hash,
    // The PLONK proof to verify.
    pub proof: PLONKProof,
}

impl OnchainTx {
    pub fn hash(&self) -> Hash {
        let (keyspace_id, new_key) = match &self.imt_mutate {
            IMTMutate::Insert(insert) => (insert.node.key, insert.node.value),
            IMTMutate::Update(update) => (update.node.key, update.new_value),
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

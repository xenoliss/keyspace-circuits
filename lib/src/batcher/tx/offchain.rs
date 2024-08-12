use imt::circuits::mutate::IMTMutate;
use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Keccak};

use crate::{
    batcher::proof::{sp1::Sp1ProofVerify, Proof},
    Hash,
};

#[derive(Debug, Deserialize, Serialize)]
pub struct OffchainTx {
    /// The IMT mutate associated with this transaction.
    pub imt_mutate: IMTMutate<Hash, Hash>,
    /// The previous transaction hash.
    pub prev_tx_hash: Hash,
    /// The record proof.
    pub proof: Proof,
}

impl OffchainTx {
    pub fn hash(&self) -> Hash {
        let (keyspace_id, new_key) = match &self.imt_mutate {
            IMTMutate::Insert(insert) => (insert.node.key, insert.node.value),
            IMTMutate::Update(update) => (update.node.key, update.new_value),
        };

        let mut k = Keccak::v256();
        k.update(&self.prev_tx_hash);
        k.update(&keyspace_id);
        k.update(&new_key);

        let mut hash = [0; 32];
        k.finalize(&mut hash);
        hash
    }

    pub fn process_proof(&self, sp1_verify: Sp1ProofVerify) {
        match &self.proof {
            Proof::SP1(proof) => {
                proof.commit_to_proof(&self.imt_mutate, sp1_verify);
            }
            Proof::PLONK(proof) => {
                assert!(
                    proof.is_valid_record_proof(&self.imt_mutate),
                    "invalid PLONK proof"
                )
            }
        }
    }
}

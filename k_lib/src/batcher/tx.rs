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
        // keyspace_id = hash(hash(original_vk), hash(original_data))
        // new_key = hash(hash(new_vk), hash(new_data))
        //
        // Insertion:
        //   node_key = imt_mutate.node.key
        //
        //   v_key = record_proof.v_key
        //   current_data = record_proof.pub_inputs
        //   hash(hash(v_key), hash(current_data)) == node_key
        //
        // Update:
        //   value_hash = imt_mutate.node.value_hash
        //
        //   v_key = record_proof.v_key
        //   current_data = record_proof.pub_inputs
        //   hash(hash(v_key), hash(current_data)) == value_hash
        let keyspace_key = match &self.imt_mutate {
            IMTMutate::Insert(insert) => insert.node.key,
            IMTMutate::Update(update) => update.node.value_hash,
        };

        // If the record proof does not match with the IMTMutate, do not apply the IMTMutate.
        if keyspace_key != self.record_proof.keyspace_key() {
            return root;
        }

        // Apply the IMTMutate and returned the new root.
        self.imt_mutate.apply(root)

        // TODO: Verify tx hash.
    }
}

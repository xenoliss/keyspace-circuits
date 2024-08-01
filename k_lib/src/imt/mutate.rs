use serde::{Deserialize, Serialize};

use crate::{batcher::record_proof::RecordProof, keyspace_key};

use super::{insert::IMTInsert, node::IMTNode, update::IMTUpdate};

#[derive(Debug, Deserialize, Serialize)]
pub enum IMTMutate {
    Insert(IMTInsert),
    Update(IMTUpdate),
}

impl IMTMutate {
    /// Create a new IMTMutate for insertion.
    pub fn insert(
        old_root: [u8; 32],
        old_size: u64,
        ln_node: IMTNode,
        ln_siblings: Vec<Option<[u8; 32]>>,

        node: IMTNode,
        node_siblings: Vec<Option<[u8; 32]>>,
        updated_ln_siblings: Vec<Option<[u8; 32]>>,
    ) -> IMTMutate {
        Self::Insert(IMTInsert {
            old_root,
            old_size,
            ln_node,
            ln_siblings,
            node,
            node_siblings,
            updated_ln_siblings,
        })
    }

    /// Create a new IMTMutate for udpate.
    pub fn update(
        old_root: [u8; 32],
        size: u64,
        node: IMTNode,
        node_siblings: Vec<Option<[u8; 32]>>,
        new_value_hash: [u8; 32],
    ) -> IMTMutate {
        Self::Update(IMTUpdate {
            old_root,
            size,
            node,
            node_siblings,
            new_value_hash,
        })
    }

    /// Returns `true` if the IMTMutate is bound to the given `record_proof`.
    ///
    /// An IMTMutate is bound to a RecordProof if its relevant KeySpace Key matches with the KeySpace
    /// key recomputed from the RecordProof.
    ///
    /// For IMT insertion the relevant KeySpace Key is the node's key itself (a.k.a the Keyspace
    /// id). For IMT update the relevant KeySpace Key is the node's value hash (a.k.a the New Key).
    pub fn is_bound_to_proof(&self, record_proof: &RecordProof) -> bool {
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

        let imt_keyspace_key = match self {
            IMTMutate::Insert(insert) => insert.node.key,
            IMTMutate::Update(update) => update.node.value_hash,
        };

        // Check if the IMTUpdate relevant KeySpace key matches with the KeySpace key reocmputed
        // from the RecordProof.
        imt_keyspace_key == keyspace_key(&record_proof.v_key, &record_proof.current_data())
    }
}

impl IMTMutate {
    /// Apply the IMT mutation and return the new updated root.
    ///
    /// Before performong the mutation, the state is checked to make sure it is coherent.
    /// In case of any inconsistency, `None` is returned.
    pub fn apply(&self, old_root: [u8; 32]) -> [u8; 32] {
        match &self {
            IMTMutate::Insert(insert) => insert.apply(old_root),
            IMTMutate::Update(update) => update.apply(old_root),
        }
    }
}

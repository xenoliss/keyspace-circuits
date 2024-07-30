use serde::{Deserialize, Serialize};

use super::{insert::IMTInsert, node::IMTNode, update::IMTUpdate};

#[derive(Debug, Deserialize, Serialize)]
pub enum IMTMutate {
    Insert(IMTInsert),
    Update(IMTUpdate),
}

impl IMTMutate {
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

use serde::{Deserialize, Serialize};

use crate::imt::node::IMTNode;

use super::{imt_root, node_exists};

#[derive(Debug, Deserialize, Serialize)]
pub struct IMTUpdate {
    pub old_root: [u8; 32],
    pub size: u64,
    pub node: IMTNode,
    pub node_siblings: Vec<Option<[u8; 32]>>,
    pub new_value_hash: [u8; 32],
}

impl IMTUpdate {
    /// Apply the IMT update and return the new updated root.
    ///
    /// Before performong the update, the state is checked to make sure it is coherent.
    /// In case of any inconsistency, `None` is returned.
    pub fn apply(&self) -> Option<[u8; 32]> {
        // Verify that the node to update is already in the IMT.
        if node_exists(&self.old_root, self.size, &self.node, &self.node_siblings) {
            return None;
        }

        // Compute the new root from the updated node.
        let updated_node = IMTNode {
            value_hash: self.new_value_hash,
            ..self.node
        };

        let root_from_updated_node = imt_root(self.size, &updated_node, &self.node_siblings);

        Some(root_from_updated_node)
    }
}

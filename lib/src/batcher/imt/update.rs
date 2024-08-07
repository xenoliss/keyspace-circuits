use serde::{Deserialize, Serialize};

use super::{imt_root, node::IMTNode, node_exists};

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
    pub fn apply(&self, old_root: [u8; 32]) -> [u8; 32] {
        // Make sure the IMTMutate old_root matches the expected old_root.
        assert_eq!(old_root, self.old_root, "IMTMutate.old_root is stale");

        // Verify that the node to update is already in the IMT.
        assert!(
            node_exists(&self.old_root, self.size, &self.node, &self.node_siblings),
            "IMTMutate.node is not in the IMT"
        );

        // Compute the new root from the updated node.
        let updated_node = IMTNode {
            value_hash: self.new_value_hash,
            ..self.node
        };

        imt_root(self.size, &updated_node, &self.node_siblings)
    }
}

use serde::{Deserialize, Serialize};

use crate::imt::node::IMTNode;

use super::{imt_root, node_exists};

#[derive(Debug, Deserialize, Serialize)]
pub struct IMTInsert {
    pub old_root: [u8; 32],
    pub old_size: u64,
    pub ln_node: IMTNode,
    pub ln_siblings: Vec<Option<[u8; 32]>>,

    pub node: IMTNode,
    pub node_siblings: Vec<Option<[u8; 32]>>,
    pub updated_ln_siblings: Vec<Option<[u8; 32]>>,
}

impl IMTInsert {
    /// Apply the IMT insert and return the new updated root.
    ///
    /// Before performong the insertion, the state is checked to make sure it is coherent.
    /// In case of any inconsistency, `None` is returned.
    pub fn apply(&self) -> Option<[u8; 32]> {
        // Verify that the provided ln node is valid.
        if !self.is_valid_ln() {
            return None;
        }

        // Compute the updated root from the node and the updated ln node.
        let new_size = self.old_size + 1;

        let updated_ln = IMTNode {
            next_key: self.node.key,
            ..self.ln_node
        };

        let root_from_node = imt_root(new_size, &self.node, &self.node_siblings);
        let root_from_updated_ln = imt_root(new_size, &updated_ln, &self.updated_ln_siblings);

        // Make sure both roots are equal.
        (root_from_node == root_from_updated_ln).then_some(root_from_node)
    }

    /// Returns `true` if `self.ln_node` is a valid ln node for `self.node`.
    fn is_valid_ln(&self) -> bool {
        self.ln_node.is_ln_of(&self.node)
            && node_exists(
                &self.old_root,
                self.old_size,
                &self.ln_node,
                &self.ln_siblings,
            )
    }
}

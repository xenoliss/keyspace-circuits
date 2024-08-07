use serde::{Deserialize, Serialize};

use super::{imt_root, node::IMTNode, node_exists};

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
    pub fn apply(&self, old_root: [u8; 32]) -> [u8; 32] {
        // Make sure the IMTMutate old_root matches the expected old_root.
        assert_eq!(old_root, self.old_root, "IMTMutate.old_root is stale");

        // Verify that the provided ln node is valid.
        assert!(self.is_valid_ln(), "IMTMutate.ln_node is invalid");

        // Compute the updated root from the node and the updated ln node.
        let updated_ln = IMTNode {
            next_key: self.node.key,
            ..self.ln_node
        };

        let new_size: u64 = self.old_size + 1;
        let root_from_node = imt_root(new_size, &self.node, &self.node_siblings);
        let root_from_updated_ln = imt_root(new_size, &updated_ln, &self.updated_ln_siblings);

        // Make sure both roots are equal.
        assert_eq!(
            root_from_node, root_from_updated_ln,
            "IMTMutate.updated_ln_siblings is invalid"
        );

        root_from_node
    }

    /// Returns `true` if `self.ln_node` is a valid ln node for `self.node`.
    fn is_valid_ln(&self) -> bool {
        self.ln_node.is_ln_of(&self.node.key)
            && node_exists(
                &self.old_root,
                self.old_size,
                &self.ln_node,
                &self.ln_siblings,
            )
    }
}

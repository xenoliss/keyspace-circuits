use std::collections::HashMap;
use tiny_keccak::{Hasher, Keccak};

use k_lib::imt::node::IMTNode;

#[derive(Debug)]
pub struct IMT {
    root: [u8; 32],
    depth: u8,
    size: u64,
    nodes: HashMap<[u8; 32], IMTNode>,
    hashes: HashMap<u8, HashMap<u64, [u8; 32]>>,
}

impl IMT {
    pub fn new(depth: u8) -> Self {
        let mut nodes = HashMap::new();
        let mut hashes: HashMap<u8, HashMap<u64, [u8; 32]>> = HashMap::new();

        let node = IMTNode::default();
        let node_hash = node.hash();

        nodes.insert([0; 32], node);
        hashes.entry(depth).or_default().insert(0, node_hash);

        Self {
            root: [0; 32],
            size: 0,
            depth,
            nodes,
            hashes,
        }
    }

    pub fn insert_node(&mut self, key: [u8; 32], value_hash: [u8; 32]) {
        // Do not overflow the tree.
        let max_size = (1 << self.depth) - 1;
        if self.size == max_size {
            panic!("tree overflow")
        }

        if self.nodes.contains_key(&key) {
            panic!("key conflict")
        }

        let node_index = {
            self.size += 1;
            self.size
        };

        // Get the ln node and update it.
        let (ln_key, ln_next_key) = self.low_nullifier(&key);
        self.nodes
            .get_mut(&ln_key)
            .expect("failed to get node")
            .next_key = key;
        self.refresh_tree(&ln_key);

        // Create the new node.
        let node = IMTNode {
            index: node_index,
            key,
            value_hash,
            next_key: ln_next_key,
        };

        // Insert the new node and refresh the tree.
        self.nodes.insert(node.key, node);
        self.refresh_tree(&key);
    }

    pub fn update_node(&mut self, key: [u8; 32], value_hash: [u8; 32]) {
        let node = self.nodes.get_mut(&key).expect("node does not exist");
        node.value_hash = value_hash;
        self.refresh_tree(&key);
    }

    fn refresh_tree(&mut self, node_key: &[u8; 32]) {
        let node = self.nodes.get(node_key).expect("failed to get node");
        let mut index = node.index;

        // Recompute and cache the node hash.
        let mut hash = node.hash();
        self.hashes
            .get_mut(&self.depth)
            .expect("hashes hashmap not initialized")
            .insert(index, hash);

        // Climb up the tree and refresh the hashes.
        for level in (1..=self.depth).rev() {
            let sibling_index = index + (1 - 2 * (index % 2));
            let sibling_hash = self.hashes.entry(level).or_default().get(&sibling_index);

            let (left, right) = if index % 2 == 0 {
                (Some(&hash), sibling_hash)
            } else {
                (sibling_hash, Some(&hash))
            };

            let mut k = Keccak::v256();
            match (left, right) {
                (None, None) => unreachable!(),
                (None, Some(right)) => k.update(right),
                (Some(left), None) => k.update(left),
                (Some(left), Some(right)) => {
                    k.update(left);
                    k.update(right);
                }
            };

            k.finalize(&mut hash);

            index /= 2;

            self.hashes
                .entry(level - 1)
                .or_default()
                .insert(index, hash);
        }

        // Refresh the root hash.
        self.root = hash;
    }

    fn low_nullifier(&self, node_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        let ln = self
            .nodes
            .values()
            .reduce(|ln, node| {
                if node.key < *node_key && node.key > ln.key {
                    return node;
                }

                ln
            })
            .expect("failed to found ln node");

        (ln.key, ln.next_key)
    }
}

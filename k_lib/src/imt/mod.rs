mod insert;
mod node;
mod update;

pub mod mutate;

use tiny_keccak::{Hasher, Keccak};

use node::IMTNode;

/// Computes the IMT root.
fn imt_root(size: u64, node: &IMTNode, siblings: &Vec<[u8; 32]>) -> [u8; 32] {
    let mut hash = node.hash();

    let mut index = node.index;
    for sibling in siblings {
        let (left, right) = if index % 2 == 0 {
            (&hash, sibling)
        } else {
            (sibling, &hash)
        };

        let mut k = Keccak::v256();
        k.update(left);
        k.update(right);
        k.finalize(&mut hash);

        index /= 2;
    }

    let mut k = Keccak::v256();
    k.update(&hash);
    k.update(&size.to_be_bytes());
    k.finalize(&mut hash);

    hash
}

/// Returns `true` if th given `node` is part of the tree commited to in `root`.
fn node_exists(root: &[u8; 32], size: u64, node: &IMTNode, siblings: &Vec<[u8; 32]>) -> bool {
    *root == imt_root(size, node, siblings)
}

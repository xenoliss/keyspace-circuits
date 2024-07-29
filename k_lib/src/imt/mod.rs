mod insert;
mod update;

pub mod mutate;
pub mod node;

use tiny_keccak::{Hasher, Keccak};

use node::IMTNode;

/// Computes the IMT root.
fn imt_root(size: u64, node: &IMTNode, siblings: &Vec<Option<[u8; 32]>>) -> [u8; 32] {
    let mut hash = node.hash();

    let mut index = node.index;
    for sibling in siblings {
        let node_hash = Some(hash);

        let (left, right) = if index % 2 == 0 {
            (&node_hash, sibling)
        } else {
            (sibling, &node_hash)
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
    }

    let mut k = Keccak::v256();
    k.update(&hash);
    k.update(&size.to_be_bytes());
    k.finalize(&mut hash);

    hash
}

/// Returns `true` if the given `node` is part of the tree commited to in `root`.
fn node_exists(
    root: &[u8; 32],
    size: u64,
    node: &IMTNode,
    siblings: &Vec<Option<[u8; 32]>>,
) -> bool {
    *root == imt_root(size, node, siblings)
}

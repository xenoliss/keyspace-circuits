use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Keccak};

#[derive(Debug, Default, Deserialize, Serialize, Clone, Copy)]
pub struct IMTNode {
    pub index: u64,
    pub key: [u8; 32],
    pub value_hash: [u8; 32],
    pub next_key: [u8; 32],
}

impl IMTNode {
    pub fn hash(&self) -> [u8; 32] {
        let mut k = Keccak::v256();

        let mut h = [0u8; 32];
        // NOTE: index is intentionnaly not hashed.
        k.update(&self.key);
        k.update(&self.value_hash);
        k.update(&self.next_key);

        k.finalize(&mut h);
        h
    }

    pub fn is_ln_of(&self, node: &IMTNode) -> bool {
        self.key < node.key && ((self.next_key > node.key) || (self.next_key == [0; 32]))
    }
}

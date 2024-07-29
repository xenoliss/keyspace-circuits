use serde::{Deserialize, Serialize};

use super::tx::Tx;

#[derive(Debug, Deserialize, Serialize)]
pub struct Inputs {
    pub old_root: [u8; 32],
    pub new_root: [u8; 32],
    pub txs: Vec<Tx>,
}

impl Inputs {
    pub fn new(old_root: [u8; 32], new_root: [u8; 32], txs: Vec<Tx>) -> Self {
        Self {
            old_root,
            new_root,
            txs,
        }
    }
}

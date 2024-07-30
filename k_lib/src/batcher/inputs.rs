use serde::{Deserialize, Serialize};

use super::tx::Tx;

#[derive(Debug, Deserialize, Serialize)]
pub struct Inputs {
    pub old_root: [u8; 32],
    pub new_root: [u8; 32],

    pub txs: Vec<Tx>,
}

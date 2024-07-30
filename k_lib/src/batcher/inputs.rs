use serde::{Deserialize, Serialize};

use super::tx::Tx;

#[derive(Debug, Deserialize, Serialize)]
pub struct Inputs {
    /// Public input: the Keyspace root to start from (32 bytes).
    pub old_root: [u8; 32],
    /// Public input: the expected Keyspace root after applying the list of transactions (32 bytes).
    pub new_root: [u8; 32],

    /// Private input: the list of Keyspace transaction to process.
    pub txs: Vec<Tx>,
}

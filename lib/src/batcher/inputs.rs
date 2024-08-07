use serde::{Deserialize, Serialize};

use super::tx::Tx;

#[derive(Debug, Deserialize, Serialize)]
pub struct Inputs {
    /// Public input: the Keyspace root to start from.
    pub old_root: [u8; 32],
    /// Public input: the expected Keyspace root after applying the list of transactions.
    pub new_root: [u8; 32],
    /// Public input: the expected new transaction hash.
    pub new_tx_hash: [u8; 32],

    /// Private input: the list of transactions to process.
    pub txs: Vec<Tx>,
}

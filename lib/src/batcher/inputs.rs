use serde::{Deserialize, Serialize};

use crate::Hash;

use super::tx::Tx;

#[derive(Debug, Deserialize, Serialize)]
pub struct Inputs {
    /// Public input: the Keyspace root to start from.
    pub old_root: Hash,
    /// Public input: the expected Keyspace root after applying the list of transactions.
    pub new_root: Hash,
    /// Public input: the expected new transaction hash.
    pub new_tx_hash: Hash,

    /// Private input: the list of transactions to process.
    pub txs: Vec<Tx>,
}

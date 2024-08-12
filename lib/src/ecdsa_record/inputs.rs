use serde::{Deserialize, Serialize};

use crate::Hash;

use super::k_signature::KSignature;

#[derive(Debug, Deserialize, Serialize)]
pub struct Inputs {
    /// Public input: the Keyspace id.
    pub keyspace_id: Hash,
    /// Public input: the Keyspace current key.
    pub current_key: Hash,
    /// Public input: the Keyspace new key.
    pub new_key: Hash,

    /// Private input: the signature over keccak(keyspace_id, new_key).
    pub sig: KSignature,
    // TODO: Could it be passed at compile time? Should we enforce it somehow and how?
    /// Private input: the verifier key hash.
    pub vk_hash: Hash,
}

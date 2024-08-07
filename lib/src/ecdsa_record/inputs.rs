use serde::{Deserialize, Serialize};

use super::k_signature::KSignature;

#[derive(Debug, Deserialize, Serialize)]
pub struct Inputs {
    /// Public input: the Keyspace id.
    pub keyspace_id: [u8; 32],
    /// Public input: the Keyspace current key.
    pub current_key: [u8; 32],
    /// Public input: the Keyspace new key.
    pub new_key: [u8; 32],

    /// Private input: the signature over keccak(keyspace_id, new_key).
    pub sig: KSignature,
    // TODO: Could it be passed at compile time? Should we enforce it somehow and how?
    /// Private input: the verifier key hash.
    pub vk_hash: [u8; 32],
}

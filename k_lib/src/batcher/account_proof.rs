use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct AccountProof {
    /// Veryfing key of the Account program.
    v_key: [u32; 8],
    /// Public inputs of the Account program.
    pub_inputs: Vec<u8>,
}

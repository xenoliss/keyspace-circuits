use serde::{Deserialize, Serialize};

use super::{current_data::CurrentData, k_signature::KSignature};

#[derive(Debug, Deserialize, Serialize)]
pub struct Inputs {
    /// Public input: the public key x, y coordinates (64 bytes).
    pub current_data: CurrentData,
    /// Public input: the new Keyspace key (32 bytes).
    pub new_key: [u8; 32],

    /// Private input: the siginature of the `new_key`.
    pub sig: KSignature,
}

impl Inputs {
    pub fn public_key(&self) -> &[u8] {
        &self.current_data.0[..64]
    }
}

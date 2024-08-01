use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct RecordProof {
    /// Veryfing key of the Account program.
    pub v_key: [u32; 8],
    /// Public inputs of the Account program.
    pub pub_inputs: Vec<u8>,
}

impl RecordProof {
    pub fn current_data(&self) -> [u8; 256] {
        self.pub_inputs[..256]
            .try_into()
            .expect("invalid current data")
    }

    pub fn new_key(&self) -> [u8; 32] {
        self.pub_inputs[256..288]
            .try_into()
            .expect("invalid current data")
    }
}

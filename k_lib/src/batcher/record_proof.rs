use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Keccak};

#[derive(Debug, Deserialize, Serialize)]
pub struct RecordProof {
    /// Veryfing key of the Account program.
    pub v_key: [u32; 8],
    /// Public inputs of the Account program.
    pub pub_inputs: Vec<u8>,
}

impl RecordProof {
    pub fn keyspace_key(&self) -> [u8; 32] {
        let mut k = Keccak::v256();

        let mut key = [0u8; 32];
        k.update(&words_to_bytes_le(&self.v_key));
        k.update(&self.current_data_hash());
        k.finalize(&mut key);

        key
    }

    fn current_data_hash(&self) -> [u8; 32] {
        let mut k = Keccak::v256();

        let mut key = [0u8; 32];
        k.update(&self.pub_inputs[..256]);
        k.finalize(&mut key);

        key
    }
}

fn words_to_bytes_le(words: &[u32]) -> Vec<u8> {
    words
        .iter()
        .flat_map(|word| word.to_le_bytes().to_vec())
        .collect::<Vec<_>>()
}

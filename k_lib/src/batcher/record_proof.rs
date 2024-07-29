use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct RecordProof {
    /// Veryfing key of the Account program.
    v_key: [u32; 8],
    /// Public inputs of the Account program.
    pub_inputs: Vec<u8>,
}

impl RecordProof {
    #[cfg(not(target_os = "zkvm"))]
    pub fn verify(&self) {}

    #[cfg(target_os = "zkvm")]
    pub fn verify(&self) {
        use sha2::{Digest, Sha256};

        let public_values = sp1_zkvm::io::read_vec();

        let public_values_digest = Sha256::digest(public_values);
        sp1_zkvm::lib::verify::verify_sp1_proof(&self.v_key, &public_values_digest.into());
    }
}

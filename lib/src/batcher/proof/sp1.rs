use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{batcher::imt::mutate::IMTMutate, keyspace_key_from_storage_hash};

pub type Sp1ProofVerify = fn(&[u32; 8], &[u8; 32]);

#[derive(Debug, Deserialize, Serialize)]
pub struct SP1Proof {
    /// The record verifier key hash.
    pub record_vk_hash: [u8; 32],
    /// The storage hash.
    pub storage_hash: [u8; 32],
}

impl SP1Proof {
    pub fn commit_to_proof(&self, imt_mutate: &IMTMutate, sp1_verify: Sp1ProofVerify) {
        let (keyspace_id, current_key, new_key) = match imt_mutate {
            IMTMutate::Insert(insert) => (insert.node.key, insert.node.key, insert.node.value_hash),
            IMTMutate::Update(update) => (
                update.node.key,
                update.node.value_hash,
                update.new_value_hash,
            ),
        };

        // Ensure the provided `record_vk_hash` matches with the `current_key`.
        //
        // This check is CRITICAL to ensure that the provided `record_vk_hash` is indeed the one
        // that has control over the KeySpace id. Without this check a malicious user could provide
        // an arbitrary `record_vk_hash` and update any KeySpace record.
        assert_eq!(
            current_key,
            keyspace_key_from_storage_hash(&self.record_vk_hash, &self.storage_hash),
            "record_vk_hash does not match with current_key"
        );

        let mut pub_inputs = [0; 96];
        pub_inputs[..32].copy_from_slice(&keyspace_id);
        pub_inputs[32..64].copy_from_slice(&current_key);
        pub_inputs[64..].copy_from_slice(&new_key);

        let public_values_digest = Sha256::digest(pub_inputs);

        let vk_hash = bytes_to_words_be(&self.record_vk_hash)
            .try_into()
            .expect("failed to convert vk hash");

        sp1_verify(&vk_hash, &public_values_digest.into());
    }
}

/// Converts a byte array in big endian to a slice of words.
pub fn bytes_to_words_be(bytes: &[u8]) -> Vec<u32> {
    bytes
        .chunks_exact(4)
        .map(|chunk| u32::from_be_bytes(chunk.try_into().unwrap()))
        .collect::<Vec<_>>()
}

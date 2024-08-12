use imt::circuits::mutate::IMTMutate;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{keyspace_key_from_storage_hash, Hash};

pub type Sp1ProofVerify = fn(&[u32; 8], &Hash);

#[derive(Debug, Deserialize, Serialize)]
pub struct SP1Proof {
    /// The record verifier key hash.
    pub record_vk_hash: Hash,
    /// The storage hash.
    pub storage_hash: Hash,
}

impl SP1Proof {
    pub fn commit_to_proof(&self, imt_mutate: &IMTMutate<Hash, Hash>, sp1_verify: Sp1ProofVerify) {
        let (keyspace_id, current_key, new_key) = match imt_mutate {
            IMTMutate::Insert(insert) => (insert.node.key, insert.node.key, insert.node.value),
            IMTMutate::Update(update) => (update.node.key, update.node.value, update.new_value),
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

#[cfg(test)]
mod tests {
    use imt::circuits::imt::Imt;
    use tiny_keccak::Keccak;

    use crate::hash_storage;

    use super::*;

    #[test]
    #[should_panic(expected = "record_vk_hash does not match with current_key")]
    fn test_commit_to_proof_insert_invalid_vk_hash() {
        let mut imt = Imt::new(Keccak::v256);

        // Initital values used to compute the KeySpace id.
        let record_vk_hash = [16; 32];
        let storage = [42; 32];
        let storage_hash = hash_storage(&storage);
        let keyspace_id = keyspace_key_from_storage_hash(&record_vk_hash, &storage_hash);

        // Insert the new node.
        let new_storage_hash = [16; 32];
        let new_key = keyspace_key_from_storage_hash(&record_vk_hash, &new_storage_hash);
        let insert = imt.insert_node(keyspace_id, new_key);

        // Set the `record_vk_hash` to an arbitrary one that is does not match with the `keyspace_id`.
        let sut = SP1Proof {
            record_vk_hash: [0xaa; 32],
            storage_hash,
        };

        let sp1_verify: Sp1ProofVerify = |_vk_hash, _public_values_digest| {};
        sut.commit_to_proof(&insert, sp1_verify);
    }

    #[test]
    fn test_commit_to_proof_insert() {
        let mut imt = Imt::new(Keccak::v256);

        // Initital values used to compute the KeySpace id.
        let record_vk_hash = [16; 32];
        let storage = [42; 32];
        let storage_hash = hash_storage(&storage);
        let keyspace_id = keyspace_key_from_storage_hash(&record_vk_hash, &storage_hash);

        // Insert the new node.
        let new_storage_hash = [16; 32];
        let new_key = keyspace_key_from_storage_hash(&record_vk_hash, &new_storage_hash);
        let insert = imt.insert_node(keyspace_id, new_key);

        let sut = SP1Proof {
            record_vk_hash,
            storage_hash,
        };

        let sp1_verify: Sp1ProofVerify = |_vk_hash, _public_values_digest| {};
        sut.commit_to_proof(&insert, sp1_verify);
    }

    #[test]
    #[should_panic(expected = "record_vk_hash does not match with current_key")]
    fn test_commit_to_proof_update_invalid_vk_hash() {
        let mut imt = Imt::new(Keccak::v256);

        // Initital values used to compute the KeySpace id.
        let record_vk_hash = [16; 32];
        let storage = [42; 32];
        let storage_hash = hash_storage(&storage);
        let keyspace_id = keyspace_key_from_storage_hash(&record_vk_hash, &storage_hash);

        // Do a 1st insertion.
        let storage = [16; 32];
        let old_storage_hash = hash_storage(&storage);
        let new_key = keyspace_key_from_storage_hash(&record_vk_hash, &storage_hash);
        imt.insert_node(keyspace_id, new_key);

        // Then perform the update.
        let storage = [05; 32];
        let storage_hash = hash_storage(&storage);
        let new_key = keyspace_key_from_storage_hash(&record_vk_hash, &storage_hash);
        let update = imt.update_node(keyspace_id, new_key);

        // Set the `record_vk_hash` to an arbitrary one that is does not match with the `current_key`.
        let sut = SP1Proof {
            record_vk_hash: [0xaa; 32],
            storage_hash: old_storage_hash,
        };

        let sp1_verify: Sp1ProofVerify = |_vk_hash, _public_values_digest| {};
        sut.commit_to_proof(&update, sp1_verify);
    }

    #[test]
    #[should_panic(expected = "record_vk_hash does not match with current_key")]
    fn test_commit_to_proof_update() {
        let mut imt = Imt::new(Keccak::v256);

        // Initital values used to compute the KeySpace id.
        let record_vk_hash = [16; 32];
        let storage = [42; 32];
        let storage_hash = hash_storage(&storage);
        let keyspace_id = keyspace_key_from_storage_hash(&record_vk_hash, &storage_hash);

        // Do a 1st insertion.
        let storage = [16; 32];
        let old_storage_hash = hash_storage(&storage);
        let new_key = keyspace_key_from_storage_hash(&record_vk_hash, &storage_hash);
        imt.insert_node(keyspace_id, new_key);

        // Then perform the update.
        let storage = [05; 32];
        let storage_hash = hash_storage(&storage);
        let new_key = keyspace_key_from_storage_hash(&record_vk_hash, &storage_hash);
        let update = imt.update_node(keyspace_id, new_key);

        let sut = SP1Proof {
            record_vk_hash,
            storage_hash: old_storage_hash,
        };

        let sp1_verify: Sp1ProofVerify = |_vk_hash, _public_values_digest| {};
        sut.commit_to_proof(&update, sp1_verify);
    }
}

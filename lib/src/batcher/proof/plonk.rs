use gnark_bn254_verifier::{verify, Fr, ProvingSystem};
use imt::circuits::mutate::IMTMutate;
use num_bigint::BigUint;
use num_traits::Num;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{keyspace_key_from_storage_hash, Hash};

#[derive(Debug, Deserialize, Serialize)]
pub struct PLONKProof {
    /// The plonk's record verifier key.
    pub vk: Vec<u8>,
    /// The record proof data.
    pub proof: Vec<u8>,
    /// The plonk's verifier key hash. SP1's plonk proofs take the vk_hash as the first public input.
    pub vk_hash: String,

    /// The storage hash.
    pub storage_hash: Hash,
}

impl PLONKProof {
    pub fn is_valid_record_proof(&self, imt_mutate: &IMTMutate<Hash, Hash>) -> bool {
        let (keyspace_id, current_key, new_key) = match imt_mutate {
            IMTMutate::Insert(insert) => (insert.node.key, insert.node.key, insert.node.value),
            IMTMutate::Update(update) => (update.node.key, update.node.value, update.new_value),
        };

        // Ensure the provided `record_vk_hash` matches with the `current_key`.
        //
        // This check is CRITICAL to ensure that the provided `record_vk_hash` is indeed the one
        // that has control over the KeySpace id. Without this check a malicious user could provide
        // an arbitrary `record_vk_hash` and update any KeySpace record.
        let vk_hash_num = BigUint::from_str_radix(&self.vk_hash, 10).unwrap();
        let vk_hash = &vk_hash_num.to_bytes_be().as_slice().try_into().unwrap();
        let keyspace_key = keyspace_key_from_storage_hash(vk_hash, &self.storage_hash);
        assert_eq!(current_key, keyspace_key);

        let mut pub_inputs = [0; 96];
        pub_inputs[..32].copy_from_slice(&keyspace_id);
        pub_inputs[32..64].copy_from_slice(&current_key);
        pub_inputs[64..].copy_from_slice(&new_key);

        let public_values_digest = Sha256::digest(pub_inputs);

        verify(
            &self.proof,
            &self.vk,
            &[
                Fr::from(vk_hash_num),
                Fr::from(BigUint::from_bytes_be(&public_values_digest)),
            ],
            ProvingSystem::Plonk,
        )
    }
}

use gnark_bn254_verifier::{verify, Fr, ProvingSystem};
use imt::circuits::mutate::IMTMutate;
use num_bigint::BigUint;
use num_traits::Num;
use serde::{Deserialize, Serialize};
use sp1_core::io::SP1PublicValues;

use crate::{keyspace_key_from_storage_hash, Hash};

#[derive(Debug, Deserialize, Serialize)]
pub struct PLONKProof {
    /// The plonk's record verifier key.
    pub vk: Vec<u8>,
    /// The record proof data.
    pub proof: Vec<u8>,
    /// The hash of the plonk's verifier key.
    pub plonk_vk_hash: String,
    /// The hash of the zkVM's verifier key, which is different from hash(PLONKProof.vk).
    pub zkvm_vk_hash: String,

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
        let vk_hash_num = BigUint::from_str_radix(&self.plonk_vk_hash, 10).unwrap();
        let vk_hash = &vk_hash_num.to_bytes_be().as_slice().try_into().unwrap();
        let keyspace_key = keyspace_key_from_storage_hash(vk_hash, &self.storage_hash);
        assert_eq!(current_key, keyspace_key);

        let mut pub_inputs = [0; 96];
        pub_inputs[..32].copy_from_slice(&keyspace_id);
        pub_inputs[32..64].copy_from_slice(&current_key);
        pub_inputs[64..].copy_from_slice(&new_key);
        // There are two potential ways to calculate the public values digest after concatenating the values. The straightforward way is Sha256::digest(), which is what commit_to_proof does in lib::batcher::proof::sp1. The other way is to use SP1PublicValues::hash(), which calculates the hash slightly differently. This latter method matches the public inputs digest obtained during serialize_plonk().
        let public_values_digest = SP1PublicValues::from(&pub_inputs).hash();

        verify(
            &self.proof,
            &self.vk,
            &[
                Fr::from(BigUint::from_str_radix(&self.zkvm_vk_hash, 10).unwrap()),
                Fr::from(public_values_digest),
            ],
            ProvingSystem::Plonk,
        )
    }
}

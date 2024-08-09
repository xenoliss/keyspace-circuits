use std::{
    fs::File,
    io::{Read, Write},
};

use serde::{Deserialize, Serialize};
use sp1_sdk::SP1ProofWithPublicValues;

#[derive(Serialize, Deserialize)]
struct StorageProof {
    storage_hash: [u8; 32],
    serialized_proof: String,
}

pub fn save_record_proof_to_file(
    proof: &SP1ProofWithPublicValues,
    storage_hash: [u8; 32],
    file: &str,
) {
    let serialized_proof = serde_json::to_string(&proof).expect("failed to serialize proof");
    let proof = StorageProof {
        storage_hash,
        serialized_proof,
    };
    let proof = serde_json::to_string(&proof).expect("failed to serialize proof");

    let mut file = File::create(file).expect("failed to create file");
    file.write_all(proof.as_bytes())
        .expect("failed to save proof in storage");
}

pub fn load_record_proof_from_file(file: &str) -> ([u8; 32], SP1ProofWithPublicValues) {
    let mut file = File::open(file).expect("failed to open filee");

    let mut proof = String::new();
    file.read_to_string(&mut proof)
        .expect("failed to read proof from storage");

    let storage_proof: StorageProof =
        serde_json::from_str(&proof).expect("failed to deserialize storage proof");

    let record_proof: SP1ProofWithPublicValues =
        serde_json::from_str(&storage_proof.serialized_proof).expect("failed to deserialize proof");

    (storage_proof.storage_hash, record_proof)
}

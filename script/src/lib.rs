use std::{
    fs::File,
    io::{Read, Write},
    path::PathBuf,
};

use lib::Hash;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sp1_sdk::{SP1Proof, SP1ProofWithPublicValues};

#[derive(Serialize, Deserialize)]
struct StorageProof {
    storage_hash: Hash,
    // FIXME: Why serialize this as strings instead of their actual types?
    serialized_proof: String,
    serialized_plonk: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct VerifiablePlonkProof {
    pub proof: Vec<u8>,
    pub vk: Vec<u8>,
    pub plonk_vk_hash: String,
    pub zkvm_vk_hash: String,
    pub public_inputs_digest: String,
}

pub fn save_record_proof_to_file(proof: &SP1ProofWithPublicValues, storage_hash: Hash, file: &str) {
    let serialized_proof = serde_json::to_string(&proof).expect("failed to serialize proof");
    let serialized_plonk = serialize_plonk(proof);
    let proof = StorageProof {
        storage_hash,
        serialized_proof,
        serialized_plonk,
    };
    let proof = serde_json::to_string(&proof).expect("failed to serialize proof");

    let mut file = File::create(file).expect("failed to create file");
    file.write_all(proof.as_bytes())
        .expect("failed to save proof in storage");
}

pub fn load_record_proof_from_file(
    file: &str,
) -> (Hash, SP1ProofWithPublicValues, Option<VerifiablePlonkProof>) {
    let mut file = File::open(file).expect("failed to open file");

    let mut proof = String::new();
    file.read_to_string(&mut proof)
        .expect("failed to read proof from storage");

    let storage_proof: StorageProof =
        serde_json::from_str(&proof).expect("failed to deserialize storage proof");

    let record_proof: SP1ProofWithPublicValues =
        serde_json::from_str(&storage_proof.serialized_proof).expect("failed to deserialize proof");

    let plonk_proof = match storage_proof.serialized_plonk {
        Some(plonk_proof) => {
            let plonk_proof: VerifiablePlonkProof =
                serde_json::from_str(&plonk_proof).expect("failed to deserialize plonk proof");
            Some(plonk_proof)
        }
        None => None,
    };

    (storage_proof.storage_hash, record_proof, plonk_proof)
}

pub fn read_plonk_vk() -> (Vec<u8>, [u8; 32]) {
    let circuits_dir = PathBuf::from(std::env::var("HOME").unwrap())
        .join(".sp1")
        .join("circuits")
        .join("v2.0.0");

    let vk_bin_path = circuits_dir.join("plonk_vk.bin");
    println!("{}", vk_bin_path.display());
    let vk = std::fs::read(vk_bin_path).unwrap();
    let vk_hash: [u8; 32] = Sha256::digest(&vk).into();
    (vk, vk_hash)
}

fn serialize_plonk(proof: &SP1ProofWithPublicValues) -> Option<String> {
    match &proof.proof {
        SP1Proof::Compressed(_proof) => None,
        SP1Proof::Plonk(proof) => {
            // Plonk proofs are written to the user's home directory at a predictable path that is reused for each plonk proof. Read that proof, then reserialize it in our own format to write within the record proof file.
            let (vk, vk_hash) = read_plonk_vk();
            let raw_proof = hex::decode(&proof.raw_proof).unwrap();

            let verifiable_proof = VerifiablePlonkProof {
                proof: raw_proof,
                vk,
                plonk_vk_hash: BigUint::from_bytes_be(&vk_hash).to_string(),
                zkvm_vk_hash: proof.public_inputs[0].to_string(),
                public_inputs_digest: proof.public_inputs[1].to_string(),
            };

            Some(serde_json::to_string(&verifiable_proof).expect("failed to serialize plonk proof"))
        }
        _ => panic!("record proof should be compressed to be recursively verified"),
    }
}

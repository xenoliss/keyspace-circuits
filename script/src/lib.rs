use std::{
    fs::File,
    io::{Read, Write},
    path::PathBuf,
};

use lib::Hash;
use serde::{Deserialize, Serialize};
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
    pub vk_hash: String,
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

fn serialize_plonk(proof: &SP1ProofWithPublicValues) -> Option<String> {
    match &proof.proof {
        SP1Proof::Compressed(_proof) => None,
        SP1Proof::Plonk(_proof) => {
            // Plonk proofs are written to the user's home directory at a predictable path that is reused for each plonk proof. Read that proof, then reserialize it in our own format to write within the record proof file.
            let circuits_dir = PathBuf::from(std::env::var("HOME").unwrap())
                .join(".sp1")
                .join("circuits")
                .join("plonk_bn254");

            let vk_dir_entry = std::fs::read_dir(circuits_dir)
                .expect("Failed to read circuits directory")
                .next()
                .expect("No directories found in circuits directory")
                .unwrap()
                .path();

            let vk_bin_path = vk_dir_entry.join("vk.bin");

            let vk = std::fs::read(vk_bin_path).unwrap();
            let sp1_plonk_proof = SP1ProofWithPublicValues::load("proof.bin").unwrap();
            let proof = hex::decode(
                sp1_plonk_proof
                    .clone()
                    .proof
                    .try_as_plonk()
                    .unwrap()
                    .raw_proof,
            )
            .unwrap();
            let public_inputs = sp1_plonk_proof
                .proof
                .try_as_plonk()
                .unwrap()
                .public_inputs
                .clone();
            let vk_hash = &public_inputs[0];
            let public_inputs_digest = &public_inputs[1];

            let verifiable_proof = VerifiablePlonkProof {
                proof,
                vk,
                vk_hash: vk_hash.to_string(),
                public_inputs_digest: public_inputs_digest.to_string(),
            };

            Some(serde_json::to_string(&verifiable_proof).expect("failed to serialize plonk proof"))
        }
        _ => panic!("record proof should be compressed to be recursively verified"),
    }
}

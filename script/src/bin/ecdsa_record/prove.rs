use k256::{ecdsa::SigningKey, elliptic_curve::rand_core::OsRng};
use rand::Rng;
use sp1_sdk::{HashableKey, ProverClient, SP1Stdin, SP1VerifyingKey};
use tiny_keccak::{Hasher, Keccak};

use lib::ecdsa_record::{inputs::Inputs, k_signature::KSignature};

pub const ELF: &[u8] = include_bytes!("../../../../ecdsa_record/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Setup the prover client.
    let client = ProverClient::new();

    // Setup the program.
    let (pk, vk) = client.setup(ELF);

    for i in 0..10 {
        let inputs = random_inputs(&vk);

        // Setup the inputs.
        let mut stdin = SP1Stdin::new();
        stdin.write(&inputs);

        // Generate the proof.
        let proof = client
            .prove(&pk, stdin)
            .compressed()
            .run()
            .expect("failed to generate proof");
        println!("Successfully generated proof!");

        // Verify the proof.
        client.verify(&proof, &vk).expect("failed to verify proof");

        let file = format!("proofs/record_proof_{i}");
        proof.save(file).expect("failed to save proof");
    }
}

fn random_inputs(vk: &SP1VerifyingKey) -> Inputs {
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let vk_hash = vk.hash_bytes();
    let storage_hash = {
        let pk = verifying_key.to_encoded_point(false);
        let x = pk.x().unwrap();
        let y = pk.y().unwrap();

        let mut pk = [0; 64];
        pk[..32].copy_from_slice(x);
        pk[32..].copy_from_slice(y);

        let mut k = Keccak::v256();
        let mut storage_hash = [0; 32];
        k.update(&pk);
        k.finalize(&mut storage_hash);

        storage_hash
    };

    let keyspace_id = {
        let mut k = Keccak::v256();
        let mut keyspace_id = [0; 32];
        k.update(&storage_hash);
        k.update(&vk_hash);
        k.finalize(&mut keyspace_id);

        keyspace_id
    };

    let current_key = keyspace_id;

    let mut rng = rand::thread_rng();
    let new_key = rng.gen::<[u8; 32]>();

    let sig = sign_update(&signing_key, &keyspace_id, &new_key);

    Inputs {
        keyspace_id,
        current_key,
        new_key,

        sig,
        vk_hash,
    }
}

fn sign_update(signing_key: &SigningKey, keyspace_id: &[u8; 32], new_key: &[u8; 32]) -> KSignature {
    let msg_hash = {
        let mut k = Keccak::v256();
        let mut msg_hash = [0; 32];
        k.update(keyspace_id);
        k.update(new_key);
        k.finalize(&mut msg_hash);

        msg_hash
    };

    let (sig, recid) = signing_key.sign_prehash_recoverable(&msg_hash).unwrap();
    let sig_bytes = sig.to_bytes();

    KSignature {
        sig: sig_bytes.into(),
        recid: recid.to_byte(),
    }
}

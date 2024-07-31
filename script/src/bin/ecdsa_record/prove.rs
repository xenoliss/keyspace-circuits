use k256::{ecdsa::SigningKey, elliptic_curve::rand_core::OsRng};
use rand::Rng;
use sp1_sdk::{ProverClient, SP1Stdin};

use k_lib::ecdsa_record::{inputs::Inputs, k_signature::sign_hash};

pub const ELF: &[u8] = include_bytes!("../../../../ecdsa_record/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Setup the prover client.
    let client = ProverClient::new();

    // Setup the program.
    let (pk, vk) = client.setup(ELF);

    for i in 0..10 {
        let args = random_inputs();

        // Setup the inputs.
        let mut stdin = SP1Stdin::new();
        stdin.write(&args);

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

fn random_inputs() -> Inputs {
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let mut rng = rand::thread_rng();
    let new_key = rng.gen();
    let sig = sign_hash(&signing_key, &new_key);

    Inputs {
        current_data: verifying_key.into(),
        new_key,
        sig,
    }
}

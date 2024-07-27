use k256::{ecdsa::SigningKey, elliptic_curve::rand_core::OsRng};

use k_lib::ecdsa_account::{Inputs, KPublicKey, KSignature};
use sp1_sdk::{ProverClient, SP1Stdin};

pub const ELF: &[u8] = include_bytes!("../../../../ecdsa_account/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Setup the prover client.
    let client = ProverClient::new();

    // Setup the program.
    let (pk, vk) = client.setup(ELF);

    for i in 0..1 {
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

        let file = format!("proofs/account_proof_{i}");
        proof.save(file).expect("Failed to save proof");
    }
}

fn random_inputs() -> Inputs {
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let new_key = [42; 32];
    let (sig, recid) = signing_key.sign_prehash_recoverable(&new_key).unwrap();

    let pk = KPublicKey::from(verifying_key);
    let sig = KSignature::from(&(sig, recid));

    Inputs::new(new_key, pk, sig)
}

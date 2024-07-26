use k256::sha2::{Digest, Sha256};
use k256::{ecdsa::SigningKey, elliptic_curve::rand_core::OsRng};

use sp1_sdk::{ProverClient, SP1Stdin};

pub const ELF: &[u8] = include_bytes!("../../../../ecdsa_account/elf/riscv32im-succinct-zkvm-elf");

/// The ECDSA account program inputs.
pub struct ECDSAAccoutProgramInputs {
    inputs_hash: [u8; 32],
    new_key: [u8; 32],
    pk: Vec<u8>,
    sig: Vec<u8>,
}

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Setup the prover client.
    let client = ProverClient::new();

    // Setup the program.
    let (pk, vk) = client.setup(ELF);

    let args = generate_inputs();

    // Setup the inputs.
    let mut stdin = SP1Stdin::new();
    stdin.write::<[u8; 32]>(&args.inputs_hash);
    stdin.write::<[u8; 32]>(&args.new_key);
    stdin.write_slice(&args.pk);
    stdin.write_slice(&args.sig);

    // Generate the proof.
    let proof = client
        .prove(&pk, stdin)
        .run()
        .expect("failed to generate proof");
    println!("Successfully generated proof!");

    // Verify the proof.
    client.verify(&proof, &vk).expect("failed to verify proof");
}

pub fn generate_inputs() -> ECDSAAccoutProgramInputs {
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let new_key = [42; 32];

    let (sig, recid) = signing_key.sign_prehash_recoverable(&new_key).unwrap();
    let sig_bytes = sig.to_bytes();

    let mut sig = Vec::with_capacity(65);
    sig.extend_from_slice(&sig_bytes);
    sig.push(recid.to_byte());

    let pk = verifying_key.to_encoded_point(false);
    let x = pk.x().unwrap();
    let y = pk.y().unwrap();

    let mut pk = Vec::with_capacity(x.len() + y.len());
    pk.extend_from_slice(x);
    pk.extend_from_slice(y);

    let inputs_hash = Sha256::new()
        .chain_update(new_key)
        .chain_update(&pk)
        .finalize()
        .to_vec()
        .try_into()
        .unwrap();

    // Parse the command line arguments.
    ECDSAAccoutProgramInputs {
        inputs_hash,
        new_key,
        pk,
        sig,
    }
}

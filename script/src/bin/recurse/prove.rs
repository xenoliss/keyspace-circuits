use k256::sha2::{Digest, Sha256};
use k256::{ecdsa::SigningKey, elliptic_curve::rand_core::OsRng};

use sp1_sdk::{HashableKey, ProverClient, SP1Proof, SP1Stdin};

pub const ELF: &[u8] = include_bytes!("../../../../recurse/elf/riscv32im-succinct-zkvm-elf");
const ECDSA_ACCOUNT_ELF: &[u8] =
    include_bytes!("../../../../ecdsa_account/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Initialize the proving client.
    let client = ProverClient::new();

    // Setup the proving and verifying keys.
    let (recurse_pk, _) = client.setup(ELF);
    let (account_pk, account_vk) = client.setup(ECDSA_ACCOUNT_ELF);

    // Generate the account proof.
    let account_proof = tracing::info_span!("generate account proof").in_scope(|| {
        let mut stdin = SP1Stdin::new();
        let args = generate_account_inputs();
        stdin.write::<[u8; 32]>(&args.inputs_hash);
        stdin.write::<[u8; 32]>(&args.new_key);
        stdin.write_slice(&args.pk);
        stdin.write_slice(&args.sig);

        client
            .prove(&account_pk, stdin)
            .compressed()
            .run()
            .expect("account proving failed")
    });

    println!("Account proof generated");

    tracing::info_span!("recurse proof").in_scope(|| {
        let mut stdin = SP1Stdin::new();

        // Write the verification key.
        let vk = account_vk.hash_bytes();
        stdin.write::<[u8; 32]>(&vk);

        // Write the public value.
        let public_values = account_proof.public_values.to_vec();
        stdin.write::<Vec<u8>>(&public_values);

        // Write the proof.
        //
        // Note: this data will not actually be read by the recurse program, instead it will be
        // witnessed by the prover during the recursive recurse process inside SP1 itself.
        let SP1Proof::Compressed(proof) = account_proof.proof else {
            panic!()
        };
        stdin.write_proof(proof, account_vk.vk);

        // Generate the plonk bn254 proof.
        client
            .prove(&recurse_pk, stdin)
            .plonk()
            .run()
            .expect("recurse proving failed");
    });

    println!("YAYYYYYY");
}

/// The ECDSA account program inputs.
pub struct ECDSAAccoutProgramInputs {
    inputs_hash: [u8; 32],
    new_key: [u8; 32],
    pk: Vec<u8>,
    sig: Vec<u8>,
}

pub fn generate_account_inputs() -> ECDSAAccoutProgramInputs {
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

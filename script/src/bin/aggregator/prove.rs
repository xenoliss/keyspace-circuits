use k_lib::aggregator::Inputs;
use sp1_sdk::{HashableKey, ProverClient, SP1Proof, SP1ProofWithPublicValues, SP1Stdin};

pub const ELF: &[u8] = include_bytes!("../../../../aggregator/elf/riscv32im-succinct-zkvm-elf");

const ECDSA_ACCOUNT_ELF: &[u8] =
    include_bytes!("../../../../ecdsa_account/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Initialize the proving client.
    let client = ProverClient::new();

    // Setup the proving and verifying keys.
    let (aggregator_pk, _) = client.setup(ELF);
    let (_, account_vk) = client.setup(ECDSA_ACCOUNT_ELF);

    let account_proof = SP1ProofWithPublicValues::load("proofs/account_proof_0")
        .expect("failed to load account proof from file");

    let mut stdin = SP1Stdin::new();

    let account_pub_hash = account_proof
        .public_values
        .as_ref()
        .try_into()
        .expect("failed to convert account_pub_hash");

    // Write the verification key.
    let inputs = Inputs::new(account_vk.hash_u32(), account_pub_hash);
    stdin.write(&inputs);

    // Write the proof.
    //
    // Note: this data will not actually be read by the aggregator program, instead it will be
    // witnessed by the prover during the recursive aggregator process inside SP1 itself.
    let SP1Proof::Compressed(proof) = account_proof.proof else {
        panic!()
    };
    stdin.write_proof(proof, account_vk.vk);

    // Generate the plonk bn254 proof.
    client
        .prove(&aggregator_pk, stdin)
        .plonk()
        .run()
        .expect("aggregator proving failed");
}

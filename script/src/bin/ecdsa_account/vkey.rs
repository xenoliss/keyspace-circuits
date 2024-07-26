use sp1_sdk::{HashableKey, ProverClient};

pub const ELF: &[u8] = include_bytes!("../../../../ecdsa_account/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Setup the prover client.
    let client = ProverClient::new();

    // Setup the program.
    let (_, vk) = client.setup(ELF);

    // Print the verification key.
    println!("Program Verification Key: {}", vk.bytes32());
}

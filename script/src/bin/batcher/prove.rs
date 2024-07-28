use sp1_sdk::{HashableKey, ProverClient, SP1Proof, SP1ProofWithPublicValues, SP1Stdin};

pub const ELF: &[u8] = include_bytes!("../../../../batcher/elf/riscv32im-succinct-zkvm-elf");

const ECDSA_RECORD_ELF: &[u8] =
    include_bytes!("../../../../ecdsa_record/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    todo!();
    // // Setup the logger.
    // sp1_sdk::utils::setup_logger();

    // // Initialize the proving client.
    // let client = ProverClient::new();

    // // Setup the proving and verifying keys.
    // let (batcher_pk, _) = client.setup(ELF);
    // let (_, account_vk) = client.setup(ECDSA_RECORD_ELF);

    // let mut stdin = SP1Stdin::new();
    // let v_key_hash = account_vk.hash_u32();

    // let txs = (0..5)
    //     .map(|i| {
    //         let file = format!("proofs/account_proof_{i}");
    //         let account_proof = SP1ProofWithPublicValues::load(file)
    //             .expect("failed to load account proof from file");

    //         // Write the proof.
    //         //
    //         // Note: this data will not actually be read by the batcher program, instead it will be
    //         // witnessed by the prover during the recursive batcher process inside SP1 itself.
    //         let SP1Proof::Compressed(proof) = account_proof.proof else {
    //             panic!()
    //         };
    //         stdin.write_proof(proof, account_vk.vk.clone());

    //         let account_pub_hash = account_proof.public_values.to_vec();
    //         Tx::from((v_key_hash, account_pub_hash))
    //     })
    //     .collect::<Vec<_>>();

    // stdin.write(&txs);

    // // Generate the plonk bn254 proof.
    // client
    //     .prove(&batcher_pk, stdin)
    //     .plonk()
    //     .run()
    //     .expect("batcher proving failed");
}

use k_lib::batcher::{inputs::Inputs, program::Program, record_proof::RecordProof, tx::Tx};
use sp1_sdk::{HashableKey, ProverClient, SP1Proof, SP1ProofWithPublicValues, SP1Stdin};

pub const ELF: &[u8] = include_bytes!("../../../../batcher/elf/riscv32im-succinct-zkvm-elf");

const ECDSA_RECORD_ELF: &[u8] =
    include_bytes!("../../../../ecdsa_record/elf/riscv32im-succinct-zkvm-elf");

mod imt;

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Initialize the proving client.
    let client = ProverClient::new();

    // Setup the proving and verifying keys.
    let (batcher_pk, _) = client.setup(ELF);
    let (_, record_vk) = client.setup(ECDSA_RECORD_ELF);

    let mut tree = imt::Imt::new(32);
    let old_root = tree.root;

    let v_key_hash = record_vk.hash_u32();
    let mut stdin = SP1Stdin::new();

    let txs = (0..10)
        .map(|i| {
            // Read the Record Proof from file storage.
            let file = format!("proofs/record_proof_{i}");
            let record_proof = SP1ProofWithPublicValues::load(file)
                .expect("failed to load record proof from file");

            let SP1Proof::Compressed(proof) = record_proof.proof else {
                panic!()
            };
            stdin.write_proof(proof, record_vk.vk.clone());

            // Build the Record Proof input.
            let record_proof = RecordProof {
                v_key: v_key_hash,
                pub_inputs: record_proof.public_values.to_vec(),
            };

            let keyspace_id = record_proof.keyspace_key();

            // Mutate the tree for the re-computed Keyspace id.
            let imt_mutate = tree.insert_node(keyspace_id, [3; 32]);

            // Build a transaction to send.
            Tx {
                record_proof,
                imt_mutate,
            }
        })
        .collect::<Vec<_>>();

    let new_root = tree.root;

    let inputs = Inputs {
        old_root,
        new_root,
        txs,
    };

    // Make sure the inputs is valid by fake running our the batcher program.
    Program::run(&inputs);

    // Generate the proof for it.
    stdin.write(&inputs);
    client
        .prove(&batcher_pk, stdin)
        .plonk()
        .run()
        .expect("batcher proving failed");
}

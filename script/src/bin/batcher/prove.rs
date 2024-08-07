use sp1_sdk::{HashableKey, ProverClient, SP1Proof, SP1ProofWithPublicValues, SP1Stdin};

use lib::batcher::{inputs::Inputs, tx::Tx};

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

    let v_key_hash = record_vk.hash_bytes();
    let mut stdin = SP1Stdin::new();

    let mut tx_hash = [0; 32];
    let txs = (0..10)
        .map(|i| {
            // Read the Record Proof from file storage.
            let file = format!("proofs/record_proof_{i}");
            let record_proof = SP1ProofWithPublicValues::load(file)
                .expect("failed to load record proof from file");

            let proof = match record_proof.proof {
                SP1Proof::Compressed(proof) => proof,
                _ => panic!("record proof should be compressed to be recursively verified"),
            };

            stdin.write_proof(proof, record_vk.vk.clone());

            // Fetch the KeySpace id and the new key from the recrd proof public inputs.
            let keyspace_id = record_proof.public_values.as_slice()[..32]
                .try_into()
                .expect("invalid record proof public inputs");

            let new_key = record_proof.public_values.as_slice()[64..]
                .try_into()
                .expect("invalid record proof public inputs");

            // Generate the IMTMutate.
            let imt_mutate = tree.insert_node(keyspace_id, new_key);

            // Build an Offchain transaction to send.
            let tx = Tx::offchain(imt_mutate, tx_hash, v_key_hash);

            tx_hash = tx.hash();

            tx
        })
        .collect::<Vec<_>>();

    let new_root = tree.root;

    let inputs = Inputs {
        old_root,
        new_root,
        new_tx_hash: tx_hash,

        txs,
    };

    // Generate the proof for it.
    stdin.write(&inputs);
    client
        .prove(&batcher_pk, stdin)
        .plonk()
        .run()
        .expect("batcher proving failed");
}

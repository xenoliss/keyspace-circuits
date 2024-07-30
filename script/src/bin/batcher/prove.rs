use k_lib::batcher::{inputs::Inputs, record_proof::RecordProof, tx::Tx};
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

    let v_key_hash = record_vk.hash_u32();

    let mut tree = imt::Imt::new(2);
    let old_root = tree.root;

    let imt_mutates = vec![
        {
            let mutate = tree.insert_node([1; 32], [1; 32]);
            mutate.apply().expect("failed to apply mutate 1");

            mutate
        },
        {
            let mutate = tree.insert_node([2; 32], [2; 32]);
            mutate.apply().expect("failed to apply mutate 1");

            mutate
        },
        {
            let mutate = tree.update_node([2; 32], [42; 32]);
            mutate.apply().expect("failed to apply mutate 1");

            mutate
        },
        {
            let mutate = tree.insert_node([3; 32], [3; 32]);
            mutate.apply().expect("failed to apply mutate 1");

            mutate
        },
    ];

    let new_root = tree.root;

    let mut stdin = SP1Stdin::new();

    let txs = imt_mutates
        .into_iter()
        .enumerate()
        .map(|(i, mutate)| {
            let file = format!("proofs/record_proof_{i}");
            let record_proof = SP1ProofWithPublicValues::load(file)
                .expect("failed to load record proof from file");

            let SP1Proof::Compressed(proof) = record_proof.proof else {
                panic!()
            };
            stdin.write_proof(proof, record_vk.vk.clone());

            let pub_inputs = record_proof.public_values.to_vec();
            let record_proof = RecordProof {
                v_key: v_key_hash,
                pub_inputs,
            };

            Tx {
                record_proof,
                imt_mutate: mutate,
            }
        })
        .collect::<Vec<_>>();

    let inputs = Inputs {
        old_root,
        new_root,
        txs,
    };

    stdin.write(&inputs);

    client
        .prove(&batcher_pk, stdin)
        .run()
        .expect("batcher proving failed");
}

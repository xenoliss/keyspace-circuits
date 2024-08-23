use k256::{ecdsa::SigningKey, elliptic_curve::rand_core::OsRng};
use rand::Rng;
use sp1_sdk::{
    HashableKey, ProverClient, SP1ProofWithPublicValues, SP1ProvingKey, SP1Stdin, SP1VerifyingKey,
};
use tiny_keccak::{Hasher, Keccak};

use keyspace_script::{read_plonk_vk, save_record_proof_to_file};
use lib::{
    ecdsa_record::{inputs::Inputs, k_signature::KSignature},
    keyspace_key_from_storage_hash,
};

pub const ELF: &[u8] = include_bytes!("../../../../ecdsa_record/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Setup the prover client.
    let client = ProverClient::new();

    // Setup the program.
    let (pk, vk) = client.setup(ELF);

    // We don't know the verifying key for the plonk wrapper until we generate one and read it from SP1's scratch directory.
    prove_random_record_as_plonk(&client, &pk, &[0; 32]);
    let (_plonk_vk, plonk_vk_hash) = read_plonk_vk();

    for i in 0..1 {
        let (proof, storage_hash) = prove_random_record_as_plonk(&client, &pk, &plonk_vk_hash);

        // Verify the proof.
        client.verify(&proof, &vk).expect("failed to verify proof");

        // Serialize the proof and write it to storage.
        // NOTE: Also save the `storage_hash` as it is needed when building the actual txs.
        save_record_proof_to_file(
            &proof,
            storage_hash,
            &format!("proofs/record_proof_{i}.json"),
        );
    }
}

fn prove_random_record_as_plonk(
    client: &ProverClient,
    pk: &SP1ProvingKey,
    vk_hash: &[u8; 32],
) -> (SP1ProofWithPublicValues, [u8; 32]) {
    let (storage_hash, inputs) = random_inputs(vk_hash);

    // Setup the inputs.
    let mut stdin = SP1Stdin::new();
    stdin.write(&inputs);

    // Generate the proof.
    let proof = client
        .prove(&pk, stdin)
        .plonk()
        .run()
        .expect("failed to generate proof");
    (proof, storage_hash)
}

fn prove_random_record_as_sp1(
    client: ProverClient,
    pk: &SP1ProvingKey,
    vk: &SP1VerifyingKey,
) -> (SP1ProofWithPublicValues, [u8; 32]) {
    let (storage_hash, inputs) = random_inputs(&vk.hash_bytes());

    // Setup the inputs.
    let mut stdin = SP1Stdin::new();
    stdin.write(&inputs);

    // Generate the proof.
    let proof = client
        .prove(&pk, stdin)
        .compressed()
        .run()
        .expect("failed to generate proof");
    (proof, storage_hash)
}

fn random_inputs(vk_hash: &[u8; 32]) -> ([u8; 32], Inputs) {
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let storage_hash = {
        let pk = verifying_key.to_encoded_point(false);
        let x = pk.x().unwrap();
        let y = pk.y().unwrap();

        let mut pk = [0; 64];
        pk[..32].copy_from_slice(x);
        pk[32..].copy_from_slice(y);

        let mut k = Keccak::v256();
        let mut storage_hash = [0; 32];
        k.update(&pk);
        k.finalize(&mut storage_hash);

        storage_hash
    };

    let keyspace_id = keyspace_key_from_storage_hash(&vk_hash, &storage_hash);
    let current_key = keyspace_id;

    let mut rng = rand::thread_rng();
    let new_key = rng.gen::<[u8; 32]>();

    let sig = sign_update(&signing_key, &keyspace_id, &new_key);

    let inputs = Inputs {
        keyspace_id,
        current_key,
        new_key,

        sig,
        vk_hash: *vk_hash,
    };

    (storage_hash, inputs)
}

fn sign_update(signing_key: &SigningKey, keyspace_id: &[u8; 32], new_key: &[u8; 32]) -> KSignature {
    let msg_hash = {
        let mut k = Keccak::v256();
        let mut msg_hash = [0; 32];
        k.update(keyspace_id);
        k.update(new_key);
        k.finalize(&mut msg_hash);

        msg_hash
    };

    let (sig, recid) = signing_key.sign_prehash_recoverable(&msg_hash).unwrap();
    let sig_bytes = sig.to_bytes();

    KSignature {
        sig: sig_bytes.into(),
        recid: recid.to_byte(),
    }
}

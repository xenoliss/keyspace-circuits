#![no_main]
sp1_zkvm::entrypoint!(main);

use sha2::{Digest, Sha256};

use k_lib::batcher::{inputs::Inputs, program::Program};

pub fn main() {
    let inputs = sp1_zkvm::io::read::<Inputs>();
    Program::run(&inputs);

    // Commit to the public inputs.
    sp1_zkvm::io::commit(&inputs.old_root);
    sp1_zkvm::io::commit(&inputs.new_root);

    verify_record_proofs(&inputs)
}

fn verify_record_proofs(inputs: &Inputs) {
    inputs.txs.iter().for_each(|tx| {
        let proof = &tx.record_proof;
        let public_values_digest = Sha256::digest(&proof.pub_inputs);
        sp1_zkvm::lib::verify::verify_sp1_proof(&proof.v_key, &public_values_digest.into());
    });
}

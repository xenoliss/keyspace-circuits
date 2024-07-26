#![no_main]
sp1_zkvm::entrypoint!(main);

use sha2_v0_10_8::{Digest, Sha256};

pub fn main() {
    // Public inputs.
    let inputs_hash = sp1_zkvm::io::read::<[u8; 32]>();
    sp1_zkvm::io::commit_slice(&inputs_hash);

    // Semi public inputs.
    let new_key = sp1_zkvm::io::read::<[u8; 32]>();
    let pk = sp1_zkvm::io::read_vec();

    // Private inputs.
    let sig = sp1_zkvm::io::read_vec();

    // Verify the hash of the semi public inputs.
    let hash = Sha256::new()
        .chain_update(new_key)
        .chain_update(&pk)
        .finalize()
        .to_vec();

    assert!(hash == inputs_hash);

    // Verify the signature against the pk.
    let recovered_key = sp1_lib::secp256k1::ecrecover(&sig.try_into().unwrap(), &new_key).unwrap();

    assert!(pk == recovered_key[1..]);
}

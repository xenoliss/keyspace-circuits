#![no_main]

use sha2_v0_10_8::Digest;
use sha2_v0_10_8::Sha256;
use sp1_lib::utils::bytes_to_words_le;

sp1_zkvm::entrypoint!(main);

pub fn main() {
    // Read the verification keys.
    let vk = sp1_zkvm::io::read::<[u8; 32]>();

    // Read the public values.
    let public_values = sp1_zkvm::io::read_vec();

    let public_values_digest = Sha256::digest(public_values);
    sp1_zkvm::lib::verify::verify_sp1_proof(
        &bytes_to_words_le(&vk).try_into().unwrap(),
        &public_values_digest.into(),
    );
}

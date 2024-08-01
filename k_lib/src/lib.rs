use tiny_keccak::{Hasher, Keccak};

// Programs
pub mod batcher;
pub mod ecdsa_record;
pub mod multisig_record;

// Libs
pub mod imt;

pub fn keyspace_key(vk_hash: &[u32; 8], current_data: &[u8; 256]) -> [u8; 32] {
    let mut k = Keccak::v256();

    let mut key = [0u8; 32];
    k.update(&words_to_bytes_le(vk_hash));
    k.update(&current_data_hash(current_data));
    k.finalize(&mut key);

    key
}

fn current_data_hash(current_data: &[u8; 256]) -> [u8; 32] {
    let mut k = Keccak::v256();

    let mut key = [0u8; 32];
    k.update(current_data);
    k.finalize(&mut key);

    key
}

fn words_to_bytes_le(words: &[u32]) -> Vec<u8> {
    words
        .iter()
        .flat_map(|word| word.to_le_bytes().to_vec())
        .collect::<Vec<_>>()
}

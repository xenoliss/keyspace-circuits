use tiny_keccak::{Hasher, Keccak};

pub mod batcher;
pub mod ecdsa_record;

pub type Hash = [u8; 32];

pub fn keyspace_key_from_storage(vk_hash: &Hash, storage: &[u8]) -> Hash {
    // Compute the `storage_hash`: keccack(storage).
    let mut k = Keccak::v256();
    let mut storage_hash = [0; 32];
    k.update(storage);
    k.finalize(&mut storage_hash);

    keyspace_key_from_storage_hash(vk_hash, &storage_hash)
}

pub fn keyspace_key_from_storage_hash(vk_hash: &Hash, storage_hash: &Hash) -> Hash {
    // Compute the Keyspace key: keccack(storage_hash, vk_hash).
    let mut k = Keccak::v256();
    let mut key = [0; 32];
    k.update(storage_hash);
    k.update(vk_hash);
    k.finalize(&mut key);

    key
}

use tiny_keccak::{Hasher, Keccak};

use crate::keyspace_key_from_storage;

use super::inputs::Inputs;

pub struct Program;

impl Program {
    pub fn run(inputs: &Inputs) {
        // Compute the `msg_hash`: keccack(keyspace_id, new_key).
        let mut k = Keccak::v256();
        let mut msg_hash = [0; 32];
        k.update(&inputs.keyspace_id);
        k.update(&inputs.new_key);
        k.finalize(&mut msg_hash);

        // Recover the public key from the signature and `msg_hash`.
        let recovered_pub_key = inputs.sig.ecrecover(&msg_hash);

        // Recover the `current_key`: keccack(storage_hash, vk_hash).
        let current_key = keyspace_key_from_storage(&inputs.vk_hash, &recovered_pub_key);

        // Ensure the recovered `current_key` matches with the one passed as public input.
        assert_eq!(inputs.current_key, current_key);
    }
}

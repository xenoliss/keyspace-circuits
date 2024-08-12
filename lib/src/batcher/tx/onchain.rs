use imt::circuits::mutate::IMTMutate;
use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Keccak};

use crate::{batcher::proof::plonk::PLONKProof, Hash};

#[derive(Debug, Deserialize, Serialize)]
pub struct OnchainTx {
    /// The IMT mutate associated with this transaction.
    pub imt_mutate: IMTMutate<Hash, Hash>,
    /// The previous transaction hash.
    pub prev_tx_hash: Hash,
    // The PLONK proof to verify.
    pub proof: PLONKProof,
}

impl OnchainTx {
    pub fn hash(&self) -> Hash {
        let (keyspace_id, new_key) = match &self.imt_mutate {
            IMTMutate::Insert(insert) => (insert.node.key, insert.node.value),
            IMTMutate::Update(update) => (update.node.key, update.new_value),
        };

        let mut k = Keccak::v256();
        k.update(&self.prev_tx_hash);
        k.update(&keyspace_id);
        k.update(&new_key);
        k.update(&self.proof.data);

        let mut hash = [0; 32];
        k.finalize(&mut hash);
        hash
    }

    pub fn is_valid_record_proof(&self) -> bool {
        self.proof.is_valid_record_proof(&self.imt_mutate)
    }
}

#[cfg(test)]
mod tests {

    use imt::circuits::imt::Imt;

    use super::*;

    #[test]
    fn test_hash_insert() {
        let mut imt = Imt::new(Keccak::v256);

        let node_key = [1; 32];
        let node_value = [42; 32];
        let insert = imt.insert_node(node_key, node_value);

        let sut = OnchainTx {
            imt_mutate: insert,
            prev_tx_hash: [0xff; 32],
            proof: PLONKProof {
                record_vk_hash: [0xff; 32],
                data: vec![1, 2, 3, 4, 5],
            },
        };
        let hash = sut.hash();

        let mut expected_keccak = Keccak::v256();
        expected_keccak.update(&sut.prev_tx_hash);
        expected_keccak.update(&node_key);
        expected_keccak.update(&node_value);
        expected_keccak.update(&sut.proof.data);
        let mut expected_hash = [0u8; 32];
        expected_keccak.finalize(&mut expected_hash);

        assert_eq!(hash, expected_hash);
    }

    #[test]
    fn test_hash_update() {
        let mut imt = Imt::new(Keccak::v256);

        let node_key = [1; 32];
        let node_value = [42; 32];
        imt.insert_node(node_key, node_value);
        let node_value = [43; 32];
        let update = imt.update_node(node_key, node_value);

        let offchain_tx = OnchainTx {
            imt_mutate: update,
            prev_tx_hash: [0xff; 32],
            proof: PLONKProof {
                record_vk_hash: [0xff; 32],
                data: vec![1, 2, 3, 4, 5],
            },
        };
        let hash = offchain_tx.hash();

        let mut expected_keccak = Keccak::v256();
        expected_keccak.update(&offchain_tx.prev_tx_hash);
        expected_keccak.update(&node_key);
        expected_keccak.update(&node_value);
        expected_keccak.update(&offchain_tx.proof.data);
        let mut expected_hash = [0u8; 32];
        expected_keccak.finalize(&mut expected_hash);

        assert_eq!(hash, expected_hash);
    }
}

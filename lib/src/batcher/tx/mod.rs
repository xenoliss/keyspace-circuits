use serde::{Deserialize, Serialize};

pub mod offchain;
pub mod onchain;

use offchain::OffchainTx;
use onchain::OnchainTx;

use super::imt::mutate::IMTMutate;

#[derive(Debug, Deserialize, Serialize)]
pub enum Tx {
    Offchain(OffchainTx),
    Onchain(OnchainTx),
}

impl Tx {
    pub fn offchain(
        imt_mutate: IMTMutate,
        prev_tx_hash: [u8; 32],
        record_vk_hash: [u8; 32],
        storage_hash: [u8; 32],
    ) -> Self {
        Self::Offchain(OffchainTx {
            imt_mutate,
            prev_tx_hash,
            record_vk_hash,
            storage_hash,
        })
    }

    pub fn onchain(
        imt_mutate: IMTMutate,
        prev_tx_hash: [u8; 32],
        record_vk_hash: [u8; 32],
        record_proof: Vec<u8>,
    ) -> Self {
        Self::Onchain(OnchainTx {
            imt_mutate,
            prev_tx_hash,
            record_vk_hash,
            record_proof,
        })
    }

    pub fn hash(&self) -> [u8; 32] {
        match self {
            Tx::Offchain(offchain) => offchain.hash(),
            Tx::Onchain(onchain) => onchain.hash(),
        }
    }

    pub fn apply_imt_mutate(&self, old_root: &[u8; 32]) -> [u8; 32] {
        match self {
            Tx::Offchain(offchain) => offchain.imt_mutate.apply(*old_root),
            Tx::Onchain(onchain) => onchain.imt_mutate.apply(*old_root),
        }
    }
}

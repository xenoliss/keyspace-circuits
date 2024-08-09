use serde::{Deserialize, Serialize};

pub mod offchain;
pub mod onchain;

use offchain::OffchainTx;
use onchain::OnchainTx;

use super::{
    imt::mutate::IMTMutate,
    proof::{plonk::PLONKProof, Proof},
};

#[derive(Debug, Deserialize, Serialize)]
pub enum Tx {
    Offchain(OffchainTx),
    Onchain(OnchainTx),
}

impl Tx {
    pub fn offchain(imt_mutate: IMTMutate, prev_tx_hash: [u8; 32], proof: Proof) -> Self {
        Self::Offchain(OffchainTx {
            imt_mutate,
            prev_tx_hash,
            proof,
        })
    }

    pub fn onchain(imt_mutate: IMTMutate, prev_tx_hash: [u8; 32], proof: PLONKProof) -> Self {
        Self::Onchain(OnchainTx {
            imt_mutate,
            prev_tx_hash,
            proof,
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

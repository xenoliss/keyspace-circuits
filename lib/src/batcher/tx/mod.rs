use anyhow::Result;
use imt::circuits::mutate::IMTMutate;
use serde::{Deserialize, Serialize};
use tiny_keccak::Keccak;

pub mod offchain;
pub mod onchain;

use offchain::OffchainTx;
use onchain::OnchainTx;

use crate::Hash;

use super::proof::{plonk::PLONKProof, Proof};

#[derive(Debug, Deserialize, Serialize)]
pub enum Tx {
    Offchain(OffchainTx),
    Onchain(OnchainTx),
}

impl Tx {
    pub fn offchain(imt_mutate: IMTMutate<Hash, Hash>, prev_tx_hash: Hash, proof: Proof) -> Self {
        Self::Offchain(OffchainTx {
            imt_mutate,
            prev_tx_hash,
            proof,
        })
    }

    pub fn onchain(
        imt_mutate: IMTMutate<Hash, Hash>,
        prev_tx_hash: Hash,
        proof: PLONKProof,
    ) -> Self {
        Self::Onchain(OnchainTx {
            imt_mutate,
            prev_tx_hash,
            proof,
        })
    }

    pub fn hash(&self) -> Hash {
        match self {
            Tx::Offchain(offchain) => offchain.hash(),
            Tx::Onchain(onchain) => onchain.hash(),
        }
    }

    pub fn verify_imt_mutate(&self, old_root: &Hash) -> Result<Hash> {
        match self {
            Tx::Offchain(offchain) => offchain.imt_mutate.verify(Keccak::v256, *old_root),
            Tx::Onchain(onchain) => onchain.imt_mutate.verify(Keccak::v256, *old_root),
        }
    }
}

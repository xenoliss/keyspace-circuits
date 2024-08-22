use plonk::PLONKProof;
use serde::{Deserialize, Serialize};
use sp1::SP1Proof;

pub mod plonk;
pub mod sp1;

#[derive(Debug, Deserialize, Serialize)]
pub enum Proof {
    SP1(SP1Proof),
    PLONK(PLONKProof),
}

impl Proof {
    pub fn sp1(record_vk_hash: [u8; 32], storage_hash: [u8; 32]) -> Self {
        Self::SP1(SP1Proof {
            record_vk_hash,
            storage_hash,
        })
    }

    pub fn plonk(vk: &[u8], data: Vec<u8>) -> Self {
        Self::PLONK(PLONKProof {
            vk: vk.into(),
            data,
        })
    }
}

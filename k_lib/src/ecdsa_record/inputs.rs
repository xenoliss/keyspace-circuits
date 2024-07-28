use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{k_public_key::KPublicKey, k_signature::KSignature};

#[derive(Debug, Deserialize, Serialize)]
pub struct Inputs {
    pub pub_inputs_hash: [u8; 32],
    pub new_key: [u8; 32],
    pub pk: KPublicKey,
    pub sig: KSignature,
}

impl Inputs {
    pub fn new(new_key: [u8; 32], pk: KPublicKey, sig: KSignature) -> Self {
        let pub_inputs_hash = Inputs::pub_hash(&new_key, &pk);

        Self {
            new_key,
            pk,
            sig,
            pub_inputs_hash,
        }
    }

    pub fn to_commit(&self) -> &[u8; 32] {
        &self.pub_inputs_hash
    }

    pub fn expected_pub_hash(&self) -> [u8; 32] {
        Inputs::pub_hash(&self.new_key, &self.pk)
    }

    fn pub_hash(new_key: &[u8; 32], pk: &KPublicKey) -> [u8; 32] {
        Sha256::new()
            .chain_update(new_key)
            .chain_update(pk.0)
            .finalize()
            .to_vec()
            .try_into()
            .expect("failed to compute the public hash")
    }
}

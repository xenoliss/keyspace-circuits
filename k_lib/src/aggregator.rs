use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct Tx {
    v_key: [u32; 8],
    account_pub_hash: [u8; 32],
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Inputs {
    tx: Tx,
}

impl Inputs {
    pub fn new(v_key: [u32; 8], account_pub_hash: [u8; 32]) -> Self {
        Self {
            tx: Tx {
                v_key,
                account_pub_hash,
            },
        }
    }

    pub fn to_commit(&self) -> &Tx {
        &self.tx
    }
}

pub struct Circuit;

impl Circuit {
    pub fn run(inputs: &Inputs) {
        let v_key = inputs.tx.v_key;
        let account_pub_hash = inputs.tx.account_pub_hash;

        //TODO: This should not be in the lib...
        #[cfg(target_os = "zkvm")]
        {
            use sha2::{Digest, Sha256};

            let public_values_digest = Sha256::digest(account_pub_hash);
            sp1_zkvm::lib::verify::verify_sp1_proof(&v_key, &public_values_digest.into());
        }
    }
}

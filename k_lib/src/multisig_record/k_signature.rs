use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone)]
pub struct KSignature {
    pub owner_index: u8,
    pub sig: [u8; 64],
    pub recid: u8,
}

pub fn sign_hash(signing_key: &SigningKey, hash: &[u8; 32], owner_index: u8) -> KSignature {
    let (sig, recid) = signing_key.sign_prehash_recoverable(hash).unwrap();
    let sig_bytes = sig.to_bytes();

    KSignature {
        owner_index,
        sig: sig_bytes.into(),
        recid: recid.to_byte(),
    }
}

impl Serialize for KSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = Vec::with_capacity(66);
        bytes.push(self.owner_index);
        bytes.extend_from_slice(&self.sig);
        bytes.push(self.recid);
        serializer.serialize_bytes(&bytes)
    }
}

impl<'de> Deserialize<'de> for KSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: &[u8] = Deserialize::deserialize(deserializer)?;

        if bytes.len() != 66 {
            return Err(serde::de::Error::invalid_length(
                bytes.len(),
                &"expected 66 bytes",
            ));
        }

        let mut sig = [0u8; 64];
        let owner_index = bytes[0];
        sig.copy_from_slice(&bytes[1..65]);
        let recid = bytes[65];

        Ok(KSignature {
            owner_index,
            sig,
            recid,
        })
    }
}

impl KSignature {
    pub fn ecrecover(&self, msg: &[u8; 32]) -> [u8; 64] {
        VerifyingKey::recover_from_prehash(
            msg,
            &Signature::from_slice(&self.sig).expect("failed sig"),
            RecoveryId::from_byte(self.recid).expect("failed sig"),
        )
        .expect("failed recover_from_prehash")
        .to_encoded_point(false)
        .as_bytes()[1..]
            .try_into()
            .expect("failed to convert pubkey")
    }
}

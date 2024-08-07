use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug)]
pub struct KSignature {
    pub sig: [u8; 64],
    pub recid: u8,
}

impl Serialize for KSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = Vec::with_capacity(65);
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

        if bytes.len() != 65 {
            return Err(serde::de::Error::invalid_length(
                bytes.len(),
                &"expected 65 bytes",
            ));
        }

        let mut sig = [0u8; 64];
        sig.copy_from_slice(&bytes[..64]);
        let recid = bytes[64];

        Ok(KSignature { sig, recid })
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

use k256::ecdsa::VerifyingKey;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug)]
pub struct KPublicKey(pub [u8; 64]);

impl From<&VerifyingKey> for KPublicKey {
    fn from(value: &VerifyingKey) -> Self {
        let pk = value.to_encoded_point(false);
        let x = pk.x().unwrap();
        let y = pk.y().unwrap();

        let mut pk = [0; 64];
        pk[..32].copy_from_slice(x);
        pk[32..].copy_from_slice(y);

        Self(pk)
    }
}

impl Serialize for KPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for KPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: &[u8] = Deserialize::deserialize(deserializer)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::invalid_length(
                bytes.len(),
                &"expected 64 bytes",
            ));
        }

        let mut array = [0u8; 64];
        array.copy_from_slice(bytes);
        Ok(KPublicKey(array))
    }
}

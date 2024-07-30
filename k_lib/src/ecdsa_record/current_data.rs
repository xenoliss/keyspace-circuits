use k256::ecdsa::VerifyingKey;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug)]
pub struct CurrentData(pub [u8; 256]);

impl From<&VerifyingKey> for CurrentData {
    fn from(value: &VerifyingKey) -> Self {
        let pk = value.to_encoded_point(false);
        let x = pk.x().unwrap();
        let y = pk.y().unwrap();

        let mut pk = [0; 256];
        pk[..32].copy_from_slice(x);
        pk[32..64].copy_from_slice(y);

        Self(pk)
    }
}

impl Serialize for CurrentData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = Vec::with_capacity(256);
        bytes.extend_from_slice(&self.0);
        serializer.serialize_bytes(&bytes)
    }
}

impl<'de> Deserialize<'de> for CurrentData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: &[u8] = Deserialize::deserialize(deserializer)?;

        if bytes.len() != 256 {
            return Err(serde::de::Error::invalid_length(
                bytes.len(),
                &"expected 256 bytes",
            ));
        }

        let mut current_data = [0u8; 256];
        current_data.copy_from_slice(bytes);

        Ok(CurrentData(current_data))
    }
}

use num_bigint::BigUint;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{collections::HashSet, error::Error};

use super::{k_public_key::KPublicKey, k_signature::KSignature};

#[derive(Debug, Clone)]
pub struct CurrentData([u8; 256]);

impl CurrentData {
    pub fn assert_owner(&self, owner_index: u8, recovered_key: [u8; 64]) {
        // The threshold value takes up the first 64 bytes of CurrentData. Owners begin at 64 bytes.
        let owner_bytes = &self.0[(owner_index + 1) as usize * 64..(owner_index + 2) as usize * 64];
        assert_eq!(owner_bytes, &recovered_key[..]);
    }

    pub fn assert_threshold(&self, owner_indexes: Vec<u8>) {
        let unique_owners = owner_indexes.iter().collect::<HashSet<_>>();
        let threshold_bytes = &self.0[..64];
        let threshold = BigUint::from_bytes_be(threshold_bytes);
        assert!(threshold <= unique_owners.len().into());
    }
}

impl Serialize for CurrentData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for CurrentData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: &[u8] = Deserialize::deserialize(deserializer)?;
        if bytes.len() > 256 {
            return Err(serde::de::Error::invalid_length(
                bytes.len(),
                &"expected max 256 bytes",
            ));
        }

        let mut array = [0u8; 256];
        array.copy_from_slice(bytes);
        Ok(CurrentData(array))
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Inputs {
    pub current_data: CurrentData,
    pub new_key: [u8; 32],
    pub signatures: Vec<KSignature>,
}

// I wanted to use serde:ser:Error, but got tons of compiler errors and I'm not sure why.
// https://stackoverflow.com/questions/62450500/why-does-a-trait-type-boxdyn-error-error-with-sized-is-not-implemented-but
#[derive(Debug, Default)]
pub struct InputError;
impl std::fmt::Display for InputError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("Input Error")
    }
}
impl Error for InputError {}

impl Inputs {
    pub fn new(
        signers: &[KPublicKey],
        new_key: [u8; 32],
        signatures: Vec<KSignature>,
    ) -> Result<Self, InputError> {
        let current_data = serialize_signers(signers)?;
        Ok(Self {
            current_data,
            new_key,
            signatures,
        })
    }
}

fn serialize_signers(signers: &[KPublicKey]) -> Result<CurrentData, InputError> {
    if signers.len() > 4 {
        return Err(InputError);
    }
    let mut bytes = [0u8; 256];
    for (i, pk) in signers.iter().enumerate() {
        bytes[i * 64..(i + 1) * 64].copy_from_slice(&pk.0);
    }
    Ok(CurrentData(bytes))
}

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub struct KPublicKey([u8; 64]);

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

#[derive(Debug)]
pub struct KSignature {
    sig: [u8; 64],
    recid: u8,
}

impl From<&(Signature, RecoveryId)> for KSignature {
    fn from(value: &(Signature, RecoveryId)) -> Self {
        let sig_bytes = value.0.to_bytes();

        Self {
            sig: sig_bytes.into(),
            recid: value.1.to_byte(),
        }
    }
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

#[derive(Debug, Deserialize, Serialize)]
pub struct Inputs {
    pub_inputs_hash: [u8; 32],
    new_key: [u8; 32],
    pk: KPublicKey,
    sig: KSignature,
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

pub struct Circuit;

impl Circuit {
    pub fn run(inputs: &Inputs) {
        let pub_hash = inputs.expected_pub_hash();
        assert_eq!(inputs.pub_inputs_hash, pub_hash);

        let recovered_key = inputs.sig.ecrecover(&inputs.new_key);
        assert_eq!(inputs.pk.0, recovered_key);
    }
}

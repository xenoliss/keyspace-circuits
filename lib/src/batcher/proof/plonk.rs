use ark_bn254::{Bn254, Fr as F};
use ark_serialize::CanonicalDeserialize as _;
use imt::circuits::mutate::IMTMutate;
use jf_plonk::{
    proof_system::{
        structs::{Proof, VerifyingKey},
        PlonkKzgSnark, UniversalSNARK as _,
    },
    transcript::StandardTranscript,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::Hash;

#[derive(Debug, Deserialize, Serialize)]
pub struct PLONKProof {
    /// The record verifier key.
    pub vk: Vec<u8>,
    /// The record proof data.
    pub data: Vec<u8>,
}

impl PLONKProof {
    pub fn is_valid_record_proof(&self, imt_mutate: &IMTMutate<Hash, Hash>) -> bool {
        let (keyspace_id, current_key, new_key) = match imt_mutate {
            IMTMutate::Insert(insert) => (insert.node.key, insert.node.key, insert.node.value),
            IMTMutate::Update(update) => (update.node.key, update.node.value, update.new_value),
        };

        // TODO: Ensure the provided `record_vk_hash` matches with the `current_key`.
        //
        // This check is CRITICAL to ensure that the provided `record_vk_hash` is indeed the one
        // that has control over the KeySpace id. Without this check a malicious user could provide
        // an arbitrary `record_vk_hash` and update any KeySpace record.

        let mut pub_inputs = [0; 96];
        pub_inputs[..32].copy_from_slice(&keyspace_id);
        pub_inputs[32..64].copy_from_slice(&current_key);
        pub_inputs[64..].copy_from_slice(&new_key);

        // FIXME: Not sure how to correctly transform the public values digest into the field elements that the verifier expects. The current approach was the result of trying to please the type system.
        let public_values_digest: Vec<_> = Sha256::digest(pub_inputs)
            .as_slice()
            .into_iter()
            .map(|x| F::from(*x))
            .collect();

        // TODO: Verify the PLONK proof
        let vk = VerifyingKey::<Bn254>::deserialize_compressed(self.vk.as_slice()).unwrap();
        // Plonk proofs from SP1 are serialized as the four-byte prefix of the vkey hash followed by the proof encoded for use in SP1's onchain verifier. We may have to  https://docs.succinct.xyz/onchain-verification/solidity-sdk.html
        let proof = Proof::<Bn254>::deserialize_compressed(self.data.as_slice()).unwrap();
        let extra_transcript_init_msg = None;

        return PlonkKzgSnark::<Bn254>::verify::<StandardTranscript>(
            &vk,
            public_values_digest.as_slice(),
            &proof,
            extra_transcript_init_msg,
        )
        .is_ok();
    }
}

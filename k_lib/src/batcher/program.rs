use super::inputs::Inputs;

pub struct Program;

impl Program {
    pub fn run(inputs: &Inputs) {
        let mut root = inputs.old_root;
        for tx in &inputs.txs {
            tx.verify(&root).expect("failed tx");
            root = tx.apply();

            //TODO: This should not be in the lib...
            // #[cfg(target_os = "zkvm")]
            // {
            //     use sha2::{Digest, Sha256};

            //     let public_values_digest = Sha256::digest(&tx.account_proof_pub_inputs);
            //     sp1_zkvm::lib::verify::verify_sp1_proof(&tx.v_key, &public_values_digest.into());
            // }
        }

        // Make sure the final root obtained after applying the txs matches with the
        // provided new_root.
        assert_eq!(root, inputs.new_root);
    }
}

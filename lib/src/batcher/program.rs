use super::{inputs::Inputs, tx::offchain::RecordProofArgs};

pub struct Program;

impl Program {
    pub fn run(inputs: &Inputs) -> Vec<RecordProofArgs> {
        let mut root = inputs.old_root;
        let mut tx_hash = [0; 32];
        let mut record_proof_args = vec![];

        for tx in &inputs.txs {
            // 1. Chain the tx hashes.
            tx_hash = tx.hash();

            // 2. Verify the record proof.
            //
            // The record proof MUST be valid for offchain txs and MAY be invalid for onchain txs.
            // If an onchain tx has an invalid record proof, it is skipped (its IMTMutate is not applied).
            match tx {
                crate::batcher::tx::Tx::Offchain(offchain) => {
                    record_proof_args.push(offchain.record_proof_args());
                }
                crate::batcher::tx::Tx::Onchain(onchain) => {
                    if !onchain.is_valid_record_proof() {
                        continue;
                    }
                }
            };

            // 3. Apply the IMTMutate and update the new root.
            root = tx.apply_imt_mutate(&root);
        }

        // Make sure the final root obtained after applying the txs matches with the provided new_root.
        assert_eq!(root, inputs.new_root);

        // Make sure the final tx hash obtained after applying the txs matches with the provided new_tx_hash.
        assert_eq!(tx_hash, inputs.new_tx_hash);

        // Return the list of record proofs (associated with offchain txs) for verification.
        record_proof_args
    }
}

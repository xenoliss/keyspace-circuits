use super::inputs::Inputs;

pub struct Program;

impl Program {
    pub fn run(inputs: &Inputs) {
        // Start from the provided old_root.
        let mut root = inputs.old_root;

        // Loop over each of the transaction and apply them one after the other while keeping
        // track of the updated root.
        for tx in &inputs.txs {
            root = tx.apply(root);
        }

        // Make sure the final root obtained after applying the txs matches with the
        // provided new_root.
        assert_eq!(root, inputs.new_root);
    }
}

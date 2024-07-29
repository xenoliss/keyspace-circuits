use super::inputs::Inputs;

pub struct Program;

impl Program {
    pub fn run(inputs: &Inputs) {
        let mut root = inputs.old_root;
        for tx in &inputs.txs {
            root = tx.apply().expect("tx failed");
        }

        // Make sure the final root obtained after applying the txs matches with the
        // provided new_root.
        assert_eq!(root, inputs.new_root);
    }
}

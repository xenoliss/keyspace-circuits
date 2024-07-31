use super::inputs::Inputs;

pub struct Program;

impl Program {
    pub fn run(inputs: &Inputs) {
        for sig in inputs.signatures.iter() {
            let recovered_key = sig.ecrecover(&inputs.new_key);
            inputs
                .current_data
                .assert_owner(sig.owner_index, recovered_key);
        }
        inputs
            .current_data
            .assert_threshold(inputs.signatures.iter().map(|s| s.owner_index).collect());
    }
}

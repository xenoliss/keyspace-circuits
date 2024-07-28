use super::inputs::Inputs;

pub struct Program;

impl Program {
    pub fn run(inputs: &Inputs) {
        let pub_hash = inputs.expected_pub_hash();
        assert_eq!(inputs.pub_inputs_hash, pub_hash);

        let recovered_key = inputs.sig.ecrecover(&inputs.new_key);
        assert_eq!(inputs.pk.0, recovered_key);
    }
}

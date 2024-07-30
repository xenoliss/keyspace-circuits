use super::inputs::Inputs;

pub struct Program;

impl Program {
    pub fn run(inputs: &Inputs) {
        // Extract the public key from the current data.
        let public_key = inputs.public_key();

        // Ensure the public key matches with the signature.
        let recovered_key = inputs.sig.ecrecover(&inputs.new_key);
        assert_eq!(public_key, recovered_key);
    }
}

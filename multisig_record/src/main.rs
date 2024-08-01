#![no_main]
sp1_zkvm::entrypoint!(main);

use k_lib::multisig_record::{inputs::Inputs, program::Program};

pub fn main() {
    let inputs = sp1_zkvm::io::read::<Inputs>();
    Program::run(&inputs);

    // Commit to the public inputs.
    sp1_zkvm::io::commit(&inputs.current_data);
    sp1_zkvm::io::commit(&inputs.new_key);
}

#![no_main]
sp1_zkvm::entrypoint!(main);

use k_lib::ecdsa_record::{inputs::Inputs, program::Program};

pub fn main() {
    let inputs = sp1_zkvm::io::read::<Inputs>();
    Program::run(&inputs);

    sp1_zkvm::io::commit(inputs.to_commit());
}

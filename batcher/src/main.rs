#![no_main]

use k_lib::batcher::{inputs::Inputs, program::Program};

sp1_zkvm::entrypoint!(main);

pub fn main() {
    let inputs = sp1_zkvm::io::read::<Inputs>();
    Program::run(&inputs);
}

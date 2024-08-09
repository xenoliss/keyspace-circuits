#![no_main]
sp1_zkvm::entrypoint!(main);

use lib::batcher::{inputs::Inputs, program::Program};

pub fn main() {
    // Parse the program inputs.
    let inputs = sp1_zkvm::io::read::<Inputs>();

    // Run the program.
    Program::run(&inputs, sp1_zkvm::lib::verify::verify_sp1_proof);

    // Commit to the public inputs.
    sp1_zkvm::io::commit_slice(&inputs.old_root);
    sp1_zkvm::io::commit_slice(&inputs.new_root);
    sp1_zkvm::io::commit_slice(&inputs.new_tx_hash);
}

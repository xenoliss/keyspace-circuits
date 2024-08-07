#![no_main]
sp1_zkvm::entrypoint!(main);

use lib::ecdsa_record::{inputs::Inputs, program::Program};

pub fn main() {
    // Parse the program inputs.
    let inputs = sp1_zkvm::io::read::<Inputs>();

    // Run the program.
    Program::run(&inputs);

    // Commit to the public inputs.
    sp1_zkvm::io::commit_slice(&inputs.keyspace_id);
    sp1_zkvm::io::commit_slice(&inputs.current_key);
    sp1_zkvm::io::commit_slice(&inputs.new_key);
}

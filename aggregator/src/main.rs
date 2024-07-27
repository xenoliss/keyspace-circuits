#![no_main]

use k_lib::aggregator::Circuit;
use k_lib::aggregator::Inputs;

sp1_zkvm::entrypoint!(main);

pub fn main() {
    let inputs = sp1_zkvm::io::read::<Inputs>();
    sp1_zkvm::io::commit(inputs.to_commit());

    Circuit::run(&inputs);
}

// Generated from the income-v1 layout by `cargo run -p pprev-types --bin gen-phase-circuit-main`.
// Do not edit by hand.
pragma circom 2.2.0;

include "phi_a.circom";

component main {public [accountHash, incomeHash, cB, amount, bind]} =
    PhiA(16, 20, 32, 3, 96);

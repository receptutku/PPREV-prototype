// Generated from the title-v1 layout by `cargo run -p pprev-types --bin gen-circuit-main`.
// Do not edit by hand.
pragma circom 2.2.0;

include "phi_r.circom";

component main {public [accountHash, ownersHash, propertyHash, propertyId, bind]} =
    PhiR(16, 4, 19, 73, 20, 32);

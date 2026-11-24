// Generated from the tenancy-v1 layout by `cargo run -p pprev-types --bin gen-phase-circuit-main`.
// Do not edit by hand.
pragma circom 2.2.0;

include "phi_s.circom";

component main {public [accountHash, propertyHash, tenantHash, dateHash, propertyId, cP, cB, engagementDay, attestationDay, bind]} =
    PhiS(16, 20, 16, 32);

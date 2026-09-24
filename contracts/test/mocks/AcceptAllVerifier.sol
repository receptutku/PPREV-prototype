// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {INotaryVerifier} from "../../src/interfaces/INotaryVerifier.sol";

/// @notice Accepts every signature. Baseline for isolating the marginal cost of ECDSA verification.
contract AcceptAllVerifier is INotaryVerifier {
    function verify(bytes32, bytes calldata) external pure returns (bool) {
        return true;
    }
}

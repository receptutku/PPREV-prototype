// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {PPREV} from "../../src/PPREV.sol";
import {PPREVEncoding} from "../../src/PPREVEncoding.sol";
import {INotaryVerifier} from "../../src/interfaces/INotaryVerifier.sol";
import {TxState, TxData} from "../../src/PPREVTypes.sol";

/// @notice Test-only subclass. Exposes the internal encoding path and lets white-box tests force
/// states that no sequence of external calls reaches.
contract PPREVHarness is PPREV {
    constructor(
        address operator,
        INotaryVerifier verifier,
        uint256 delta,
        uint256 tauLock,
        uint256 maxExpirations,
        uint256 rho
    ) PPREV(operator, verifier, delta, tauLock, maxExpirations, rho) {}

    function exposedHashTypedData(bytes32 structHash) external view returns (bytes32) {
        return _hashTypedData(structHash);
    }

    function exposedCommitment(TxData calldata txData, bytes32 policyIdR, bytes32 r) external pure returns (bytes32) {
        return PPREVEncoding.commitment(txData, policyIdR, r);
    }

    function exposedHashTxData(TxData calldata txData) external pure returns (bytes32) {
        return PPREVEncoding.hashTxData(txData);
    }

    function exposedHashRegister(PPREVEncoding.RegisterStatement memory x) external pure returns (bytes32) {
        return PPREVEncoding.hashRegister(x);
    }

    function exposedHashApply(PPREVEncoding.ApplyStatement memory x) external pure returns (bytes32) {
        return PPREVEncoding.hashApply(x);
    }

    function exposedHashSettle(PPREVEncoding.SettleStatement memory x) external pure returns (bytes32) {
        return PPREVEncoding.hashSettle(x);
    }

    function forceTxState(uint256 txId, TxState s) external {
        txState[txId] = s;
    }

    function forceExpirations(uint256 txId, uint256 expirations) external {
        listings[txId].expirations = expirations;
    }
}

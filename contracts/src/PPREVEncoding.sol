// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {TxData} from "./PPREVTypes.sol";

/// @notice Transaction commitment C_tx (Eq. (2)) and EIP-712 struct hashes of the phase statements
/// x_R, x_A, x_S (Table III). The primary type of each statement is its domain tag tag_psi.
library PPREVEncoding {
    bytes32 internal constant TX_DATA_TYPEHASH =
        keccak256("TxData(bytes32 propertyId,uint256 amount,uint256 settlementShare)");

    /// @dev tag_R
    bytes32 internal constant REGISTER_TYPEHASH = keccak256(
        "Register(bytes32 cTx,TxData txData,bytes32 policyId,address submitter,bytes32 eta,uint64 tAtt)"
        "TxData(bytes32 propertyId,uint256 amount,uint256 settlementShare)"
    );

    /// @dev tag_A
    bytes32 internal constant APPLY_TYPEHASH = keccak256(
        "Apply(uint256 txId,bytes32 cTx,TxData txData,bytes32 cB,bytes32 policyId,address submitter,bytes32 eta,"
        "uint64 tAtt)TxData(bytes32 propertyId,uint256 amount,uint256 settlementShare)"
    );

    /// @dev tag_S
    bytes32 internal constant SETTLE_TYPEHASH = keccak256(
        "Settle(uint256 engId,uint256 txId,bytes32 cTx,TxData txData,bytes32 cB,uint256 expiresAt,bytes32 policyId,"
        "address submitter,bytes32 eta,uint64 tAtt)TxData(bytes32 propertyId,uint256 amount,uint256 settlementShare)"
    );

    // Statement structs hold x_psi with txData replaced by its struct hash. Every member encodes to
    // one 32-byte word, so abi.encode(typehash, x) is typehash || encodeData(x).

    struct RegisterStatement {
        bytes32 cTx;
        bytes32 txDataHash;
        bytes32 policyId;
        address submitter;
        bytes32 eta;
        uint64 tAtt;
    }

    struct ApplyStatement {
        uint256 txId;
        bytes32 cTx;
        bytes32 txDataHash;
        bytes32 cB;
        bytes32 policyId;
        address submitter;
        bytes32 eta;
        uint64 tAtt;
    }

    struct SettleStatement {
        uint256 engId;
        uint256 txId;
        bytes32 cTx;
        bytes32 txDataHash;
        bytes32 cB;
        uint256 expiresAt;
        bytes32 policyId;
        address submitter;
        bytes32 eta;
        uint64 tAtt;
    }

    /// @notice C_tx = keccak256(txData || policyID_R || r).
    function commitment(TxData calldata txData, bytes32 policyIdR, bytes32 r) internal pure returns (bytes32) {
        return keccak256(abi.encode(txData, policyIdR, r));
    }

    function hashTxData(TxData calldata txData) internal pure returns (bytes32) {
        return keccak256(abi.encode(TX_DATA_TYPEHASH, txData));
    }

    function hashRegister(RegisterStatement memory x) internal pure returns (bytes32) {
        return keccak256(abi.encode(REGISTER_TYPEHASH, x));
    }

    function hashApply(ApplyStatement memory x) internal pure returns (bytes32) {
        return keccak256(abi.encode(APPLY_TYPEHASH, x));
    }

    function hashSettle(SettleStatement memory x) internal pure returns (bytes32) {
        return keccak256(abi.encode(SETTLE_TYPEHASH, x));
    }
}

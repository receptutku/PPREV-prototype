// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {CommonBase} from "forge-std/Base.sol";
import {TxData} from "../../src/PPREVTypes.sol";

/// @dev Phase statements as Table III lists them, with txData in full. Test-side only.
struct XR {
    bytes32 cTx;
    TxData txData;
    bytes32 policyId;
    address submitter;
    bytes32 eta;
    uint64 tAtt;
}

struct XA {
    uint256 txId;
    bytes32 cTx;
    TxData txData;
    bytes32 cB;
    bytes32 policyId;
    address submitter;
    bytes32 eta;
    uint64 tAtt;
}

struct XS {
    uint256 engId;
    uint256 txId;
    bytes32 cTx;
    TxData txData;
    bytes32 cB;
    uint256 expiresAt;
    bytes32 policyId;
    address submitter;
    bytes32 eta;
    uint64 tAtt;
}

/// @notice On-chain side of the mock notary: hashes x_psi and signs enc(tag_psi, x_psi, chainID,
/// addr_SC). The hashing is written from Table III and EIP-712 independently of src/, so tests do not
/// sign with the code they test.
abstract contract NotarySigner is CommonBase {
    uint256 internal constant NOTARY_PK = uint256(keccak256("pprev.test.notary"));
    uint256 internal constant ROGUE_PK = uint256(keccak256("pprev.test.rogue"));

    string internal constant TX_DATA_TYPE = "TxData(bytes32 propertyId,uint256 amount,uint256 settlementShare)";
    string internal constant REGISTER_TYPE =
        "Register(bytes32 cTx,TxData txData,bytes32 policyId,address submitter,bytes32 eta,uint64 tAtt)";
    string internal constant APPLY_TYPE =
        "Apply(uint256 txId,bytes32 cTx,TxData txData,bytes32 cB,bytes32 policyId,address submitter,bytes32 eta,uint64 tAtt)";
    string internal constant SETTLE_TYPE =
        "Settle(uint256 engId,uint256 txId,bytes32 cTx,TxData txData,bytes32 cB,uint256 expiresAt,bytes32 policyId,address submitter,bytes32 eta,uint64 tAtt)";

    /// @dev Where signatures are aimed; set by the fixture after deployment.
    address internal signingTarget;

    function typehashR() internal pure returns (bytes32) {
        return keccak256(bytes.concat(bytes(REGISTER_TYPE), bytes(TX_DATA_TYPE)));
    }

    function typehashA() internal pure returns (bytes32) {
        return keccak256(bytes.concat(bytes(APPLY_TYPE), bytes(TX_DATA_TYPE)));
    }

    function typehashS() internal pure returns (bytes32) {
        return keccak256(bytes.concat(bytes(SETTLE_TYPE), bytes(TX_DATA_TYPE)));
    }

    function hashTxDataTs(TxData memory d) internal pure returns (bytes32) {
        return keccak256(abi.encode(keccak256(bytes(TX_DATA_TYPE)), d.propertyId, d.amount, d.settlementShare));
    }

    /// @dev encodeData(x) without the typehash.
    function encodeDataR(XR memory x) internal pure returns (bytes memory) {
        return abi.encode(x.cTx, hashTxDataTs(x.txData), x.policyId, x.submitter, x.eta, x.tAtt);
    }

    function encodeDataA(XA memory x) internal pure returns (bytes memory) {
        return abi.encode(x.txId, x.cTx, hashTxDataTs(x.txData), x.cB, x.policyId, x.submitter, x.eta, x.tAtt);
    }

    function encodeDataS(XS memory x) internal pure returns (bytes memory) {
        bytes memory head = abi.encode(x.engId, x.txId, x.cTx, hashTxDataTs(x.txData), x.cB);
        return bytes.concat(head, abi.encode(x.expiresAt, x.policyId, x.submitter, x.eta, x.tAtt));
    }

    function structHashR(XR memory x) internal pure returns (bytes32) {
        return keccak256(bytes.concat(typehashR(), encodeDataR(x)));
    }

    function structHashA(XA memory x) internal pure returns (bytes32) {
        return keccak256(bytes.concat(typehashA(), encodeDataA(x)));
    }

    function structHashS(XS memory x) internal pure returns (bytes32) {
        return keccak256(bytes.concat(typehashS(), encodeDataS(x)));
    }

    function domainSeparatorFor(uint256 chainId, address verifyingContract) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("PPREV"),
                keccak256("1"),
                chainId,
                verifyingContract
            )
        );
    }

    function digestFor(bytes32 structHash, uint256 chainId, address verifyingContract) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(hex"1901", domainSeparatorFor(chainId, verifyingContract), structHash));
    }

    function digest(bytes32 structHash) internal view returns (bytes32) {
        return digestFor(structHash, vm.getChainId(), signingTarget);
    }

    function signDigest(uint256 pk, bytes32 d) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, d);
        return abi.encodePacked(r, s, v);
    }

    function signR(XR memory x) internal view returns (bytes memory) {
        return signDigest(NOTARY_PK, digest(structHashR(x)));
    }

    function signA(XA memory x) internal view returns (bytes memory) {
        return signDigest(NOTARY_PK, digest(structHashA(x)));
    }

    function signS(XS memory x) internal view returns (bytes memory) {
        return signDigest(NOTARY_PK, digest(structHashS(x)));
    }

    /// @dev Signs encodeData under an arbitrary typehash, for phase-substitution tests.
    function signUnderTypehash(bytes32 typehash, bytes memory encodeData) internal view returns (bytes memory) {
        return signDigest(NOTARY_PK, digest(keccak256(bytes.concat(typehash, encodeData))));
    }
}

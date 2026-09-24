// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {CommonBase} from "forge-std/Base.sol";
import {TxData} from "../../src/PPREVTypes.sol";
import {XR, XA, XS} from "./NotarySigner.sol";

/// @notice EIP-712 typed-data JSON for Foundry's independent encoder (vm.eip712HashTypedData).
/// Integers are written as decimal strings so that 256-bit values survive JSON parsing.
abstract contract TypedDataJson is CommonBase {
    string internal constant DOMAIN_TYPE_JSON = '"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},'
        '{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}]';
    string internal constant TX_DATA_TYPE_JSON = '"TxData":[{"name":"propertyId","type":"bytes32"},{"name":"amount","type":"uint256"},'
        '{"name":"settlementShare","type":"uint256"}]';
    string internal constant REGISTER_TYPE_JSON = '"Register":[{"name":"cTx","type":"bytes32"},{"name":"txData","type":"TxData"},'
        '{"name":"policyId","type":"bytes32"},{"name":"submitter","type":"address"},'
        '{"name":"eta","type":"bytes32"},{"name":"tAtt","type":"uint64"}]';
    string internal constant APPLY_TYPE_JSON = '"Apply":[{"name":"txId","type":"uint256"},{"name":"cTx","type":"bytes32"},'
        '{"name":"txData","type":"TxData"},{"name":"cB","type":"bytes32"},{"name":"policyId","type":"bytes32"},'
        '{"name":"submitter","type":"address"},{"name":"eta","type":"bytes32"},{"name":"tAtt","type":"uint64"}]';
    string internal constant SETTLE_TYPE_JSON = '"Settle":[{"name":"engId","type":"uint256"},{"name":"txId","type":"uint256"},'
        '{"name":"cTx","type":"bytes32"},{"name":"txData","type":"TxData"},{"name":"cB","type":"bytes32"},'
        '{"name":"expiresAt","type":"uint256"},{"name":"policyId","type":"bytes32"},'
        '{"name":"submitter","type":"address"},{"name":"eta","type":"bytes32"},{"name":"tAtt","type":"uint64"}]';

    function q(string memory s) internal pure returns (string memory) {
        return string.concat('"', s, '"');
    }

    function field(string memory name, string memory value) internal pure returns (string memory) {
        return string.concat('"', name, '":', value);
    }

    function hexField(string memory name, bytes32 value) internal pure returns (string memory) {
        return field(name, q(vm.toString(value)));
    }

    function uintField(string memory name, uint256 value) internal pure returns (string memory) {
        return field(name, q(vm.toString(value)));
    }

    function addressField(string memory name, address value) internal pure returns (string memory) {
        return field(name, q(vm.toString(value)));
    }

    function txDataJson(TxData memory d) internal pure returns (string memory) {
        return string.concat(
            "{",
            hexField("propertyId", d.propertyId),
            ",",
            uintField("amount", d.amount),
            ",",
            uintField("settlementShare", d.settlementShare),
            "}"
        );
    }

    function messageR(XR memory x) internal pure returns (string memory) {
        return string.concat(
            "{",
            hexField("cTx", x.cTx),
            ",",
            field("txData", txDataJson(x.txData)),
            ",",
            hexField("policyId", x.policyId),
            ",",
            addressField("submitter", x.submitter),
            ",",
            hexField("eta", x.eta),
            ",",
            uintField("tAtt", x.tAtt),
            "}"
        );
    }

    function messageA(XA memory x) internal pure returns (string memory) {
        string memory head = string.concat(
            "{",
            uintField("txId", x.txId),
            ",",
            hexField("cTx", x.cTx),
            ",",
            field("txData", txDataJson(x.txData)),
            ",",
            hexField("cB", x.cB),
            ","
        );
        return string.concat(
            head,
            hexField("policyId", x.policyId),
            ",",
            addressField("submitter", x.submitter),
            ",",
            hexField("eta", x.eta),
            ",",
            uintField("tAtt", x.tAtt),
            "}"
        );
    }

    function messageS(XS memory x) internal pure returns (string memory) {
        string memory head = string.concat(
            "{",
            uintField("engId", x.engId),
            ",",
            uintField("txId", x.txId),
            ",",
            hexField("cTx", x.cTx),
            ",",
            field("txData", txDataJson(x.txData)),
            ",",
            hexField("cB", x.cB),
            ","
        );
        return string.concat(
            head,
            uintField("expiresAt", x.expiresAt),
            ",",
            hexField("policyId", x.policyId),
            ",",
            addressField("submitter", x.submitter),
            ",",
            hexField("eta", x.eta),
            ",",
            uintField("tAtt", x.tAtt),
            "}"
        );
    }

    function domainJson(uint256 chainId, address verifyingContract) internal pure returns (string memory) {
        return string.concat(
            '{"name":"PPREV","version":"1",',
            uintField("chainId", chainId),
            ",",
            addressField("verifyingContract", verifyingContract),
            "}"
        );
    }

    function typedData(
        string memory primaryType,
        string memory primaryTypeJson,
        string memory message,
        uint256 chainId,
        address verifyingContract
    ) internal pure returns (string memory) {
        return string.concat(
            '{"types":{',
            DOMAIN_TYPE_JSON,
            ",",
            primaryTypeJson,
            ",",
            TX_DATA_TYPE_JSON,
            '},"primaryType":',
            q(primaryType),
            ',"domain":',
            domainJson(chainId, verifyingContract),
            ',"message":',
            message,
            "}"
        );
    }

    function typedDataR(XR memory x, uint256 chainId, address vc) internal pure returns (string memory) {
        return typedData("Register", REGISTER_TYPE_JSON, messageR(x), chainId, vc);
    }

    function typedDataA(XA memory x, uint256 chainId, address vc) internal pure returns (string memory) {
        return typedData("Apply", APPLY_TYPE_JSON, messageA(x), chainId, vc);
    }

    function typedDataS(XS memory x, uint256 chainId, address vc) internal pure returns (string memory) {
        return typedData("Settle", SETTLE_TYPE_JSON, messageS(x), chainId, vc);
    }
}

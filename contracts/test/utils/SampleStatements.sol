// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {TxData} from "../../src/PPREVTypes.sol";
import {XR, XA, XS} from "./NotarySigner.sol";

/// @notice Fixed statements used for the cross-language test vectors.
library SampleStatements {
    bytes32 internal constant POLICY_R = keccak256("pprev.rental.register");
    bytes32 internal constant POLICY_A = keccak256("pprev.rental.apply");
    bytes32 internal constant POLICY_S = keccak256("pprev.rental.settle");
    bytes32 internal constant SALT = keccak256("vector salt");
    address internal constant OWNER = 0x1111111111111111111111111111111111111111;
    address internal constant APPLICANT = 0x2222222222222222222222222222222222222222;

    function txData() internal pure returns (TxData memory) {
        return TxData({propertyId: bytes32("TR-06-CANKAYA-000123"), amount: 1 ether, settlementShare: 1000});
    }

    function cTx() internal pure returns (bytes32) {
        return keccak256(abi.encode(txData(), POLICY_R, SALT));
    }

    function register() internal pure returns (XR memory x) {
        x.cTx = cTx();
        x.txData = txData();
        x.policyId = POLICY_R;
        x.submitter = OWNER;
        x.eta = keccak256("vector eta R");
        x.tAtt = 1_760_000_000;
    }

    function apply_() internal pure returns (XA memory x) {
        x.txId = 1;
        x.cTx = cTx();
        x.txData = txData();
        x.cB = keccak256("vector c_B");
        x.policyId = POLICY_A;
        x.submitter = APPLICANT;
        x.eta = keccak256("vector eta A");
        x.tAtt = 1_760_000_100;
    }

    function settle() internal pure returns (XS memory x) {
        x.engId = 1;
        x.txId = 1;
        x.cTx = cTx();
        x.txData = txData();
        x.cB = keccak256("vector c_B");
        x.expiresAt = 1_761_209_700;
        x.policyId = POLICY_S;
        x.submitter = OWNER;
        x.eta = keccak256("vector eta S");
        x.tAtt = 1_760_500_000;
    }
}

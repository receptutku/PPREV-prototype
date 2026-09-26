// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Script} from "forge-std/Script.sol";
import {PPREV} from "../src/PPREV.sol";
import {INotaryVerifier} from "../src/interfaces/INotaryVerifier.sol";
import {EcdsaNotaryVerifier} from "../src/verifiers/EcdsaNotaryVerifier.sol";
import {TxData} from "../src/PPREVTypes.sol";
import {NotarySigner, XR, XA, XS} from "../test/utils/NotarySigner.sol";

/// @notice Real transactions of a complete lifecycle on a fresh deployment: Register, Apply, Engage,
/// Settle. Signatures come from the fixed test notary key of the contract tests (NOTARY_PK), whose
/// address the deployed EcdsaNotaryVerifier holds; the deployer is the operator.
///
/// Two phases, because forge simulates a script before it broadcasts: x_S carries expiresAt, which
/// Engage sets from the timestamp of the block that includes it, so Settle is signed after Engage is
/// on-chain. phaseA deploys and sends Register, Apply, Engage and writes the state to LIFECYCLE_STATE;
/// phaseB reads it and sends Settle.
/// Environment: DEPLOYER_KEY, OWNER_KEY, APPLICANT_KEY (private keys), LIFECYCLE_STATE (JSON file);
/// parameters default to D18.
/// Usage: forge script script/Lifecycle.s.sol --sig "phaseA()" --rpc-url <url> --broadcast, then
/// the same with "phaseB()".
contract Lifecycle is Script, NotarySigner {
    bytes32 internal constant POLICY_R = keccak256("pprev.rental.register");
    bytes32 internal constant POLICY_A = keccak256("pprev.rental.apply");
    bytes32 internal constant POLICY_S = keccak256("pprev.rental.settle");

    struct Params {
        uint256 delta;
        uint256 tauLock;
        uint256 maxExpirations;
        uint256 rho;
        uint256 reqEscrow;
        uint256 minCollateral;
        uint256 maxCollateral;
        uint256 collateral;
        uint256 deposit;
        uint256 amount;
    }

    uint256 internal deployerKey;
    uint256 internal ownerKey;
    uint256 internal applicantKey;
    Params internal p;
    PPREV internal pprev;
    uint256 internal seq;

    function loadEnv() internal {
        deployerKey = vm.envUint("DEPLOYER_KEY");
        ownerKey = vm.envUint("OWNER_KEY");
        applicantKey = vm.envUint("APPLICANT_KEY");
        p.delta = vm.envOr("PPREV_DELTA", uint256(300));
        p.tauLock = vm.envOr("PPREV_TAU_LOCK", uint256(14 days));
        p.maxExpirations = vm.envOr("PPREV_MAX_EXPIRATIONS", uint256(3));
        p.rho = vm.envOr("PPREV_RHO", uint256(5000));
        p.reqEscrow = vm.envOr("PPREV_REQ_ESCROW", uint256(0.05 ether));
        p.minCollateral = vm.envOr("PPREV_MIN_COLLATERAL", uint256(0.1 ether));
        p.maxCollateral = vm.envOr("PPREV_MAX_COLLATERAL", uint256(1 ether));
        p.collateral = vm.envOr("PPREV_COLLATERAL", uint256(0.5 ether));
        p.deposit = vm.envOr("PPREV_DEPOSIT", uint256(0.05 ether));
        p.amount = vm.envOr("PPREV_AMOUNT", uint256(1 ether));
    }

    function phaseA() external {
        loadEnv();
        deploy();
        (uint256 txId, TxData memory d, bytes32 r, bytes32 cTx) = register();
        uint256 appId = applyFor(txId, d, r, cTx);
        uint256 engId = engage(txId, appId);
        string memory o = "state";
        vm.serializeAddress(o, "pprev", address(pprev));
        vm.serializeUint(o, "txId", txId);
        vm.serializeUint(o, "appId", appId);
        vm.serializeUint(o, "engId", engId);
        vm.serializeBytes32(o, "r", r);
        vm.serializeBytes32(o, "cTx", cTx);
        vm.writeJson(vm.serializeUint(o, "seq", seq), vm.envString("LIFECYCLE_STATE"));
    }

    function phaseB() external {
        loadEnv();
        string memory state = vm.readFile(vm.envString("LIFECYCLE_STATE"));
        pprev = PPREV(vm.parseJsonAddress(state, ".pprev"));
        signingTarget = address(pprev);
        seq = vm.parseJsonUint(state, ".seq");
        settle(
            vm.parseJsonUint(state, ".engId"),
            vm.parseJsonUint(state, ".txId"),
            txData(),
            vm.parseJsonBytes32(state, ".r"),
            vm.parseJsonBytes32(state, ".cTx"),
            vm.parseJsonUint(state, ".appId")
        );
    }

    function txData() internal view returns (TxData memory) {
        return TxData({propertyId: bytes32("TR-06-CANKAYA-000123"), amount: p.amount, settlementShare: 0});
    }

    function deploy() internal {
        vm.startBroadcast(deployerKey);
        EcdsaNotaryVerifier verifier = new EcdsaNotaryVerifier(vm.addr(NOTARY_PK));
        pprev = new PPREV(
            vm.addr(deployerKey), INotaryVerifier(address(verifier)), p.delta, p.tauLock, p.maxExpirations, p.rho
        );
        pprev.registerPolicy(POLICY_R, POLICY_A, POLICY_S, p.reqEscrow, p.minCollateral, p.maxCollateral);
        vm.stopBroadcast();
        signingTarget = address(pprev);
    }

    function next(string memory tag) internal returns (bytes32) {
        return keccak256(abi.encode(tag, block.chainid, address(pprev), ++seq));
    }

    function now64() internal view returns (uint64) {
        return uint64(block.timestamp);
    }

    function register() internal returns (uint256 txId, TxData memory d, bytes32 r, bytes32 cTx) {
        d = txData();
        r = next("r");
        cTx = keccak256(abi.encode(d, POLICY_R, r));
        XR memory x = XR({
            cTx: cTx, txData: d, policyId: POLICY_R, submitter: vm.addr(ownerKey), eta: next("eta"), tAtt: now64()
        });
        bytes memory sigma = signR(x);
        vm.broadcast(ownerKey);
        txId = pprev.register{value: p.collateral}(cTx, d, POLICY_R, r, sigma, x.eta, x.tAtt);
    }

    function applyFor(uint256 txId, TxData memory d, bytes32 r, bytes32 cTx) internal returns (uint256 appId) {
        address applicant = vm.addr(applicantKey);
        XA memory x = XA({
            txId: txId,
            cTx: cTx,
            txData: d,
            cB: keccak256(abi.encode("c_B", applicant)),
            policyId: POLICY_A,
            submitter: applicant,
            eta: next("eta"),
            tAtt: now64()
        });
        bytes memory sigma = signA(x);
        vm.broadcast(applicantKey);
        appId = pprev.applyFor{value: p.deposit}(txId, d, r, x.cB, sigma, x.eta, x.tAtt);
    }

    function engage(uint256 txId, uint256 appId) internal returns (uint256 engId) {
        vm.broadcast(ownerKey);
        engId = pprev.engage(txId, appId);
    }

    function settle(uint256 engId, uint256 txId, TxData memory d, bytes32 r, bytes32 cTx, uint256 appId) internal {
        (,,,, bytes32 cB) = pprev.applications(appId);
        (, uint256 expiresAt,) = pprev.engagements(engId);
        XS memory x = XS({
            engId: engId,
            txId: txId,
            cTx: cTx,
            txData: d,
            cB: cB,
            expiresAt: expiresAt,
            policyId: POLICY_S,
            submitter: vm.addr(ownerKey),
            eta: next("eta"),
            tAtt: now64()
        });
        bytes memory sigma = signS(x);
        vm.broadcast(ownerKey);
        pprev.settle(engId, d, r, sigma, x.eta, x.tAtt);
    }
}

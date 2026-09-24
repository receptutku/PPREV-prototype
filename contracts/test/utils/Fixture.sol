// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Test} from "forge-std/Test.sol";
import {PPREV} from "../../src/PPREV.sol";
import {INotaryVerifier} from "../../src/interfaces/INotaryVerifier.sol";
import {EcdsaNotaryVerifier} from "../../src/verifiers/EcdsaNotaryVerifier.sol";
import {TxState, AppStatus, EngStatus, TxData, Listing, Application, Engagement} from "../../src/PPREVTypes.sol";
import {NotarySigner, XR, XA, XS} from "./NotarySigner.sol";
import {Records} from "./Records.sol";

/// @dev Arguments of one register() call. The signed statement x_R is derived from it, with
/// a_P = caller, unless a test signs a modified statement.
struct RegisterCall {
    bytes32 cTx;
    TxData txData;
    bytes32 policyIdR;
    bytes32 r;
    bytes32 eta;
    uint64 tAtt;
    uint256 collateral;
    address caller;
}

/// @dev Arguments of one applyFor() call, plus the record values the contract adds to x_A.
struct ApplyCall {
    uint256 txId;
    TxData txData;
    bytes32 r;
    bytes32 cB;
    bytes32 eta;
    uint64 tAtt;
    uint256 deposit;
    address caller;
    bytes32 cTx;
    bytes32 policyIdA;
}

/// @dev Arguments of one settle() call, plus the record values the contract adds to x_S.
struct SettleCall {
    uint256 engId;
    TxData txData;
    bytes32 r;
    bytes32 eta;
    uint64 tAtt;
    address caller;
    uint256 txId;
    bytes32 cTx;
    bytes32 cB;
    uint256 expiresAt;
    bytes32 policyIdS;
}

/// @dev State of one listing through its lifecycle.
struct Flow {
    RegisterCall rc;
    uint256 txId;
    ApplyCall ac;
    uint256 appId;
    uint256 engId;
    uint256 expiresAt;
}

/// @notice Deployment with the fixture parameters and helpers for each algorithm.
abstract contract Fixture is Test, NotarySigner {
    uint256 internal constant DELTA = 300;
    uint256 internal constant TAU_LOCK = 14 days;
    uint256 internal constant MAX_EXPIRATIONS = 3;
    uint256 internal constant RHO = 5000;
    uint256 internal constant MIN_COLLATERAL = 0.1 ether;
    uint256 internal constant MAX_COLLATERAL = 1 ether;
    uint256 internal constant REQ_ESCROW = 0.05 ether;
    uint256 internal constant RENTAL_SHARE = 0;
    uint256 internal constant SALE_SHARE = 1000;

    uint256 internal constant COLLATERAL = 0.5 ether;
    uint256 internal constant DEPOSIT = 0.05 ether;
    uint256 internal constant START_TIME = 1_760_000_000;

    bytes32 internal constant RENTAL_R = keccak256("pprev.rental.register");
    bytes32 internal constant RENTAL_A = keccak256("pprev.rental.apply");
    bytes32 internal constant RENTAL_S = keccak256("pprev.rental.settle");
    bytes32 internal constant SALE_R = keccak256("pprev.sale.register");
    bytes32 internal constant SALE_A = keccak256("pprev.sale.apply");
    bytes32 internal constant SALE_S = keccak256("pprev.sale.settle");

    PPREV internal pprev;
    EcdsaNotaryVerifier internal verifier;

    address internal operator = makeAddr("operator");
    address internal owner = makeAddr("owner");
    address internal applicant = makeAddr("applicant");
    address internal applicant2 = makeAddr("applicant2");
    address internal attacker = makeAddr("attacker");

    uint256 private seq;

    function setUp() public virtual {
        vm.warp(START_TIME);
        verifier = new EcdsaNotaryVerifier(vm.addr(NOTARY_PK));
        pprev = deploy(INotaryVerifier(address(verifier)));
        signingTarget = address(pprev);
        vm.startPrank(operator);
        pprev.registerPolicy(RENTAL_R, RENTAL_A, RENTAL_S, REQ_ESCROW, MIN_COLLATERAL, MAX_COLLATERAL);
        pprev.registerPolicy(SALE_R, SALE_A, SALE_S, REQ_ESCROW, MIN_COLLATERAL, MAX_COLLATERAL);
        vm.stopPrank();
        vm.deal(owner, 100 ether);
        vm.deal(applicant, 100 ether);
        vm.deal(applicant2, 100 ether);
        vm.deal(attacker, 100 ether);
    }

    function deploy(INotaryVerifier v) internal virtual returns (PPREV) {
        return new PPREV(operator, v, DELTA, TAU_LOCK, MAX_EXPIRATIONS, RHO);
    }

    // ------------------------------------------------------------------ values

    function next(string memory tag) internal returns (bytes32) {
        return keccak256(abi.encode(tag, ++seq));
    }

    function now64() internal view returns (uint64) {
        return uint64(vm.getBlockTimestamp());
    }

    function txDataWith(uint256 share) internal pure returns (TxData memory) {
        return TxData({propertyId: bytes32("TR-06-CANKAYA-000123"), amount: 1 ether, settlementShare: share});
    }

    /// @dev Memory structs are assigned by reference; builders copy txData so that a test altering
    /// one call cannot alter the flow it came from.
    function copyOf(TxData memory d) internal pure returns (TxData memory) {
        return TxData({propertyId: d.propertyId, amount: d.amount, settlementShare: d.settlementShare});
    }

    function commitmentOf(TxData memory d, bytes32 policyIdR, bytes32 r) internal pure returns (bytes32) {
        return keccak256(abi.encode(d, policyIdR, r));
    }

    function policyA(bytes32 policyIdR) internal pure returns (bytes32) {
        return policyIdR == SALE_R ? SALE_A : RENTAL_A;
    }

    function policyS(bytes32 policyIdR) internal pure returns (bytes32) {
        return policyIdR == SALE_R ? SALE_S : RENTAL_S;
    }

    function cBOf(address who) internal pure returns (bytes32) {
        return keccak256(abi.encode("c_B", who));
    }

    // ------------------------------------------------------------------ Register

    function registerCall(bytes32 policyIdR, uint256 share, address caller) internal returns (RegisterCall memory c) {
        c.txData = txDataWith(share);
        c.policyIdR = policyIdR;
        c.r = next("r");
        c.cTx = commitmentOf(c.txData, policyIdR, c.r);
        c.eta = next("eta");
        c.tAtt = now64();
        c.collateral = COLLATERAL;
        c.caller = caller;
    }

    function registerCall() internal returns (RegisterCall memory) {
        return registerCall(RENTAL_R, RENTAL_SHARE, owner);
    }

    function xROf(RegisterCall memory c) internal pure returns (XR memory x) {
        x.cTx = c.cTx;
        x.txData = c.txData;
        x.policyId = c.policyIdR;
        x.submitter = c.caller;
        x.eta = c.eta;
        x.tAtt = c.tAtt;
    }

    function submitRegister(RegisterCall memory c, bytes memory sigma) internal returns (uint256) {
        vm.prank(c.caller);
        return pprev.register{value: c.collateral}(c.cTx, c.txData, c.policyIdR, c.r, sigma, c.eta, c.tAtt);
    }

    function doRegister(RegisterCall memory c) internal returns (uint256) {
        return submitRegister(c, signR(xROf(c)));
    }

    // ------------------------------------------------------------------ Apply

    function applyCall(Flow memory f, address caller) internal returns (ApplyCall memory c) {
        c.txId = f.txId;
        c.txData = copyOf(f.rc.txData);
        c.r = f.rc.r;
        c.cB = cBOf(caller);
        c.eta = next("eta");
        c.tAtt = now64();
        c.deposit = DEPOSIT;
        c.caller = caller;
        c.cTx = f.rc.cTx;
        c.policyIdA = policyA(f.rc.policyIdR);
    }

    function xAOf(ApplyCall memory c) internal pure returns (XA memory x) {
        x.txId = c.txId;
        x.cTx = c.cTx;
        x.txData = c.txData;
        x.cB = c.cB;
        x.policyId = c.policyIdA;
        x.submitter = c.caller;
        x.eta = c.eta;
        x.tAtt = c.tAtt;
    }

    function submitApply(ApplyCall memory c, bytes memory sigma) internal returns (uint256) {
        vm.prank(c.caller);
        return pprev.applyFor{value: c.deposit}(c.txId, c.txData, c.r, c.cB, sigma, c.eta, c.tAtt);
    }

    function doApply(ApplyCall memory c) internal returns (uint256) {
        return submitApply(c, signA(xAOf(c)));
    }

    // ------------------------------------------------------------------ Engage

    function doEngage(Flow memory f) internal returns (uint256 engId) {
        vm.prank(f.rc.caller);
        engId = pprev.engage(f.txId, f.appId);
        f.engId = engId;
        f.expiresAt = vm.getBlockTimestamp() + TAU_LOCK;
    }

    // ------------------------------------------------------------------ Settle

    function settleCall(Flow memory f) internal returns (SettleCall memory c) {
        c.engId = f.engId;
        c.txData = copyOf(f.rc.txData);
        c.r = f.rc.r;
        c.eta = next("eta");
        c.tAtt = now64();
        c.caller = f.rc.caller;
        c.txId = f.txId;
        c.cTx = f.rc.cTx;
        c.cB = f.ac.cB;
        c.expiresAt = f.expiresAt;
        c.policyIdS = policyS(f.rc.policyIdR);
    }

    function xSOf(SettleCall memory c) internal pure returns (XS memory x) {
        x.engId = c.engId;
        x.txId = c.txId;
        x.cTx = c.cTx;
        x.txData = c.txData;
        x.cB = c.cB;
        x.expiresAt = c.expiresAt;
        x.policyId = c.policyIdS;
        x.submitter = c.caller;
        x.eta = c.eta;
        x.tAtt = c.tAtt;
    }

    function submitSettle(SettleCall memory c, bytes memory sigma) internal {
        vm.prank(c.caller);
        pprev.settle(c.engId, c.txData, c.r, sigma, c.eta, c.tAtt);
    }

    function doSettle(SettleCall memory c) internal {
        submitSettle(c, signS(xSOf(c)));
    }

    // ------------------------------------------------------------------ flows

    function flowRegistered(bytes32 policyIdR, uint256 share) internal returns (Flow memory f) {
        f.rc = registerCall(policyIdR, share, owner);
        f.txId = doRegister(f.rc);
    }

    function flowRegistered() internal returns (Flow memory) {
        return flowRegistered(RENTAL_R, RENTAL_SHARE);
    }

    function flowApplied(bytes32 policyIdR, uint256 share) internal returns (Flow memory f) {
        f = flowRegistered(policyIdR, share);
        f.ac = applyCall(f, applicant);
        f.appId = doApply(f.ac);
    }

    function flowApplied() internal returns (Flow memory) {
        return flowApplied(RENTAL_R, RENTAL_SHARE);
    }

    function flowEngaged(bytes32 policyIdR, uint256 share) internal returns (Flow memory f) {
        f = flowApplied(policyIdR, share);
        doEngage(f);
    }

    function flowEngaged() internal returns (Flow memory) {
        return flowEngaged(RENTAL_R, RENTAL_SHARE);
    }

    /// @dev Applies with `who` to an open listing and engages that application: the next round.
    function nextRound(Flow memory f, address who) internal {
        f.ac = applyCall(f, who);
        f.appId = doApply(f.ac);
        doEngage(f);
    }

    /// @dev Lets the current engagement lapse and expires it.
    function lapseAndExpire(Flow memory f) internal {
        vm.warp(f.expiresAt + 1);
        pprev.expire(f.engId);
    }

    // ------------------------------------------------------------------ record getters

    function listingOf(uint256 txId) internal view returns (Listing memory) {
        return Records.listing(pprev, txId);
    }

    function applicationOf(uint256 appId) internal view returns (Application memory a) {
        (a.txId, a.depositor, a.status, a.deposit, a.cB) = pprev.applications(appId);
    }

    function engagementOf(uint256 engId) internal view returns (Engagement memory e) {
        (e.appId, e.expiresAt, e.status) = pprev.engagements(engId);
    }

    function stateOf(uint256 txId) internal view returns (TxState) {
        return pprev.txState(txId);
    }

    // ------------------------------------------------------------------ assertions

    function assertState(uint256 txId, TxState expected) internal view {
        assertEq(uint8(pprev.txState(txId)), uint8(expected), "TxState");
    }

    function assertAppStatus(uint256 appId, AppStatus expected) internal view {
        assertEq(uint8(applicationOf(appId).status), uint8(expected), "AppStatus");
    }

    function assertEngStatus(uint256 engId, EngStatus expected) internal view {
        assertEq(uint8(engagementOf(engId).status), uint8(expected), "EngStatus");
    }
}

// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {CommonBase} from "forge-std/Base.sol";
import {StdCheats} from "forge-std/StdCheats.sol";
import {StdUtils} from "forge-std/StdUtils.sol";
import {PPREV} from "../../src/PPREV.sol";
import {TxState, AppStatus, EngStatus, TxData, Listing} from "../../src/PPREVTypes.sol";
import {NotarySigner, XR, XA, XS} from "../utils/NotarySigner.sol";
import {Records} from "../utils/Records.sol";
import {Actor} from "../mocks/Actor.sol";

/// @notice Drives random sequences of valid protocol operations. Every call it makes must succeed,
/// so a revert fails the campaign (fail_on_revert). Participants include a contract that refuses
/// payments and one that burns the payout gas.
contract Handler is CommonBase, StdCheats, StdUtils, NotarySigner {
    struct ListingInfo {
        TxData txData;
        bytes32 r;
        bytes32 cTx;
        bytes32 policyIdR;
        bytes32 policyIdA;
        bytes32 policyIdS;
        address owner;
    }

    PPREV public pprev;
    Actor public refuser;
    Actor public burner;

    bytes32 internal rentalR;
    bytes32 internal rentalA;
    bytes32 internal rentalS;
    bytes32 internal saleR;
    bytes32 internal saleA;
    bytes32 internal saleS;
    uint256 internal minCollateral;
    uint256 internal maxCollateral;
    uint256 internal reqEscrow;

    address[] internal eoas;
    address[] internal participants;
    uint256[] public txIds;
    uint256[] public appIds;
    uint256[] public engIds;
    mapping(uint256 txId => ListingInfo) internal info;
    uint256 internal seq;

    constructor(PPREV pprev_, bytes32[6] memory policies) {
        pprev = pprev_;
        signingTarget = address(pprev_);
        (rentalR, rentalA, rentalS, saleR, saleA, saleS) =
        (policies[0], policies[1], policies[2], policies[3], policies[4], policies[5]);
        (,,, reqEscrow, minCollateral, maxCollateral) = pprev_.policyRegistry(rentalR);

        refuser = new Actor();
        refuser.setMode(Actor.Mode.Refuse);
        burner = new Actor();
        burner.setMode(Actor.Mode.BurnGas);
        eoas.push(makeAddr("participant0"));
        eoas.push(makeAddr("participant1"));
        eoas.push(makeAddr("participant2"));
        for (uint256 i; i < eoas.length; ++i) {
            participants.push(eoas[i]);
        }
        participants.push(address(refuser));
        participants.push(address(burner));
        for (uint256 i; i < participants.length; ++i) {
            vm.deal(participants[i], 1e24);
        }
        vm.deal(address(this), 1e24);
    }

    // ------------------------------------------------------------------ actions

    function register(uint256 ownerSeed, uint256 collateralSeed, uint256 shareSeed, bool sale) external {
        ListingInfo memory li;
        li.owner = participants[ownerSeed % participants.length];
        li.policyIdR = sale ? saleR : rentalR;
        li.policyIdA = sale ? saleA : rentalA;
        li.policyIdS = sale ? saleS : rentalS;
        li.txData = TxData({
            propertyId: next("property"), amount: 1 ether, settlementShare: sale ? bound(shareSeed, 0, 10_000) : 0
        });
        li.r = next("r");
        li.cTx = keccak256(abi.encode(li.txData, li.policyIdR, li.r));
        XR memory x = XR({
            cTx: li.cTx,
            txData: li.txData,
            policyId: li.policyIdR,
            submitter: li.owner,
            eta: next("eta"),
            tAtt: uint64(vm.getBlockTimestamp())
        });
        bytes memory call =
            abi.encodeCall(PPREV.register, (li.cTx, li.txData, li.policyIdR, li.r, signR(x), x.eta, x.tAtt));
        uint256 txId = abi.decode(exec(li.owner, bound(collateralSeed, minCollateral, maxCollateral), call), (uint256));
        info[txId] = li;
        txIds.push(txId);
    }

    function applyTo(uint256 txSeed, uint256 applicantSeed, uint256 depositSeed) external {
        (bool found, uint256 txId) = pickOpenListing(txSeed);
        if (!found) return;
        ListingInfo storage li = info[txId];
        address who;
        for (uint256 i; i < participants.length; ++i) {
            address candidate = participants[(applicantSeed % participants.length + i) % participants.length];
            if (candidate != li.owner && pprev.pendingApp(txId, candidate) == 0) {
                who = candidate;
                break;
            }
        }
        if (who == address(0)) return;
        XA memory x;
        x.txId = txId;
        x.cTx = li.cTx;
        x.txData = li.txData;
        x.cB = keccak256(abi.encode("c_B", who));
        x.policyId = li.policyIdA;
        x.submitter = who;
        x.eta = next("eta");
        x.tAtt = uint64(vm.getBlockTimestamp());
        bytes memory call = abi.encodeCall(PPREV.applyFor, (txId, x.txData, li.r, x.cB, signA(x), x.eta, x.tAtt));
        appIds.push(abi.decode(exec(who, bound(depositSeed, reqEscrow, 1 ether), call), (uint256)));
    }

    function engage(uint256 appSeed) external {
        uint256 n = appIds.length;
        if (n == 0) return;
        uint256 start = appSeed % n;
        for (uint256 i; i < n; ++i) {
            uint256 appId = appIds[(start + i) % n];
            (uint256 txId,, AppStatus status,,) = pprev.applications(appId);
            if (status == AppStatus.Pending && isOpen(txId)) {
                bytes memory ret = exec(info[txId].owner, 0, abi.encodeCall(PPREV.engage, (txId, appId)));
                engIds.push(abi.decode(ret, (uint256)));
                return;
            }
        }
    }

    function settle(uint256 engSeed) external {
        (bool found, uint256 engId) = pickOpenEngagement(engSeed);
        if (!found) return;
        (uint256 appId, uint256 expiresAt,) = pprev.engagements(engId);
        if (vm.getBlockTimestamp() > expiresAt) return;
        (uint256 txId,,,, bytes32 cB) = pprev.applications(appId);
        ListingInfo storage li = info[txId];
        XS memory x;
        x.engId = engId;
        x.txId = txId;
        x.cTx = li.cTx;
        x.txData = li.txData;
        x.cB = cB;
        x.expiresAt = expiresAt;
        x.policyId = li.policyIdS;
        x.submitter = li.owner;
        x.eta = next("eta");
        x.tAtt = uint64(vm.getBlockTimestamp());
        exec(li.owner, 0, abi.encodeCall(PPREV.settle, (engId, x.txData, li.r, signS(x), x.eta, x.tAtt)));
    }

    function expire(uint256 engSeed, uint256 callerSeed) external {
        (bool found, uint256 engId) = pickOpenEngagement(engSeed);
        if (!found) return;
        (, uint256 expiresAt,) = pprev.engagements(engId);
        if (vm.getBlockTimestamp() <= expiresAt) vm.warp(expiresAt + 1);
        exec(eoas[callerSeed % eoas.length], 0, abi.encodeCall(PPREV.expire, (engId)));
    }

    function reclaim(uint256 appSeed) external {
        uint256 n = appIds.length;
        if (n == 0) return;
        for (uint256 i; i < n; ++i) {
            uint256 appId = appIds[(appSeed % n + i) % n];
            (, address depositor, AppStatus status,,) = pprev.applications(appId);
            if (status == AppStatus.Pending) {
                exec(depositor, 0, abi.encodeCall(PPREV.reclaim, (appId)));
                return;
            }
        }
    }

    /// @dev Acts on one call in four, so that listings live long enough to complete lifecycles.
    function cancel(uint256 txSeed) external {
        if (txSeed % 4 != 0) return;
        uint256 n = txIds.length;
        for (uint256 i; i < n; ++i) {
            uint256 txId = txIds[(txSeed / 4 % n + i) % n];
            TxState s = pprev.txState(txId);
            if (s == TxState.Active || s == TxState.Expired) {
                exec(info[txId].owner, 0, abi.encodeCall(PPREV.cancel, (txId)));
                return;
            }
        }
    }

    function withdraw(bool fromBurner) external {
        withdrawFor(fromBurner ? burner : refuser);
    }

    function warp(uint256 secondsSeed) external {
        vm.warp(vm.getBlockTimestamp() + bound(secondsSeed, 1, 20 days));
    }

    // ------------------------------------------------------------------ end-of-run drain

    /// @notice Closes every open position through the protocol's own exits.
    function drain() external {
        for (uint256 i; i < engIds.length; ++i) {
            (, uint256 expiresAt, EngStatus status) = pprev.engagements(engIds[i]);
            if (status != EngStatus.Open) continue;
            if (vm.getBlockTimestamp() <= expiresAt) vm.warp(expiresAt + 1);
            exec(eoas[0], 0, abi.encodeCall(PPREV.expire, (engIds[i])));
        }
        for (uint256 i; i < txIds.length; ++i) {
            TxState s = pprev.txState(txIds[i]);
            if (s == TxState.Active || s == TxState.Expired) {
                exec(info[txIds[i]].owner, 0, abi.encodeCall(PPREV.cancel, (txIds[i])));
            }
        }
        for (uint256 i; i < appIds.length; ++i) {
            (, address depositor, AppStatus status,,) = pprev.applications(appIds[i]);
            if (status == AppStatus.Pending) exec(depositor, 0, abi.encodeCall(PPREV.reclaim, (appIds[i])));
        }
        withdrawFor(refuser);
        withdrawFor(burner);
    }

    // ------------------------------------------------------------------ views for the invariants

    /// @notice Everything the contract owes: remaining collateral of non-terminal listings, deposits of
    /// pending applications and of applications under an open engagement, and all credits.
    function obligations() external view returns (uint256 total) {
        for (uint256 i; i < txIds.length; ++i) {
            TxState s = pprev.txState(txIds[i]);
            if (s == TxState.Active || s == TxState.Locked || s == TxState.Expired) {
                total += Records.listing(pprev, txIds[i]).collateral;
            }
        }
        for (uint256 i; i < appIds.length; ++i) {
            (,, AppStatus status, uint256 deposit,) = pprev.applications(appIds[i]);
            if (status == AppStatus.Pending) total += deposit;
        }
        for (uint256 i; i < engIds.length; ++i) {
            (uint256 appId,, EngStatus status) = pprev.engagements(engIds[i]);
            if (status == EngStatus.Open) {
                (,,, uint256 deposit,) = pprev.applications(appId);
                total += deposit;
            }
        }
        for (uint256 i; i < participants.length; ++i) {
            total += pprev.credit(participants[i]);
        }
    }

    /// @notice Number of open engagements whose listing is not LOCKED.
    function openEngagementsNotLocked() external view returns (uint256 count) {
        for (uint256 i; i < engIds.length; ++i) {
            (uint256 appId,, EngStatus status) = pprev.engagements(engIds[i]);
            if (status != EngStatus.Open) continue;
            (uint256 txId,,,,) = pprev.applications(appId);
            if (pprev.txState(txId) != TxState.Locked) ++count;
        }
    }

    /// @notice Largest number of open engagements held by a single listing.
    function maxOpenEngagementsPerListing() external view returns (uint256 maxCount) {
        for (uint256 t; t < txIds.length; ++t) {
            uint256 count;
            for (uint256 i; i < engIds.length; ++i) {
                (uint256 appId,, EngStatus status) = pprev.engagements(engIds[i]);
                if (status != EngStatus.Open) continue;
                (uint256 txId,,,,) = pprev.applications(appId);
                if (txId == txIds[t]) ++count;
            }
            if (count > maxCount) maxCount = count;
        }
    }

    /// @notice Number of listings whose state and record disagree: terminal with collateral left, or
    /// EXPIRED with the counter at maxExpirations.
    function inconsistentListings() external view returns (uint256 count) {
        for (uint256 i; i < txIds.length; ++i) {
            TxState s = pprev.txState(txIds[i]);
            Listing memory l = Records.listing(pprev, txIds[i]);
            if ((s == TxState.Settled || s == TxState.Cancelled) && l.collateral != 0) ++count;
            if (s == TxState.Expired && l.expirations >= pprev.MAX_EXPIRATIONS()) ++count;
        }
    }

    function counts() external view returns (uint256, uint256, uint256) {
        return (txIds.length, appIds.length, engIds.length);
    }

    // ------------------------------------------------------------------ internal

    function next(string memory tag) internal returns (bytes32) {
        return keccak256(abi.encode(tag, ++seq));
    }

    function pickOpenListing(uint256 seed) internal view returns (bool, uint256) {
        uint256 n = txIds.length;
        for (uint256 i; i < n; ++i) {
            uint256 txId = txIds[(seed % n + i) % n];
            if (isOpen(txId)) return (true, txId);
        }
        return (false, 0);
    }

    function pickOpenEngagement(uint256 seed) internal view returns (bool, uint256) {
        uint256 n = engIds.length;
        for (uint256 i; i < n; ++i) {
            uint256 engId = engIds[(seed % n + i) % n];
            (,, EngStatus status) = pprev.engagements(engId);
            if (status == EngStatus.Open) return (true, engId);
        }
        return (false, 0);
    }

    function isOpen(uint256 txId) internal view returns (bool) {
        TxState s = pprev.txState(txId);
        return (s == TxState.Active || s == TxState.Expired)
            && Records.listing(pprev, txId).expirations < pprev.MAX_EXPIRATIONS();
    }

    function withdrawFor(Actor a) internal {
        if (pprev.credit(address(a)) == 0) return;
        Actor.Mode m = a.mode();
        a.setMode(Actor.Mode.Accept);
        a.execute(address(pprev), 0, abi.encodeCall(PPREV.withdraw, ()));
        a.setMode(m);
    }

    function exec(address who, uint256 value, bytes memory data) internal returns (bytes memory ret) {
        if (who == address(refuser) || who == address(burner)) {
            return Actor(payable(who)).execute(address(pprev), value, data);
        }
        vm.prank(who);
        bool ok;
        (ok, ret) = address(pprev).call{value: value}(data);
        if (!ok) {
            assembly ("memory-safe") {
                revert(add(ret, 32), mload(ret))
            }
        }
    }
}

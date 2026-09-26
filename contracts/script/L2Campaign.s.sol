// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Script} from "forge-std/Script.sol";
import {PPREV} from "../src/PPREV.sol";
import {INotaryVerifier} from "../src/interfaces/INotaryVerifier.sol";
import {EcdsaNotaryVerifier} from "../src/verifiers/EcdsaNotaryVerifier.sol";
import {TxData} from "../src/PPREVTypes.sol";
import {NotarySigner, XR, XA, XS} from "../test/utils/NotarySigner.sol";

/// @notice Transactions of the Layer-2 campaign (script/measure_l2.sh), one phase at a time. Each phase
/// is simulated against the current chain state and writes the transactions to send, in order, to
/// STEPS_OUT; script/lib/l2_send.py signs, sends, and times them. Phases depend on the previous one
/// being on-chain (identifiers, expiresAt), so the campaign alternates simulation and sending.
///
/// Two deployments share one verifier: A with the fixture lock window, for Register (M times), Apply,
/// Engage, Settle, Reclaim, Cancel; B with a short lock window, for Expire. Signatures come from the
/// fixed test notary key (NOTARY_PK). Nonces and salts derive from the deployment address, so each
/// campaign uses fresh ones.
/// Environment: OWNER, APPLICANT (addresses; the owner deploys and operates), STATE (deployment
/// addresses, written by deploy and read by the other phases), STEPS_OUT, REGISTER_COUNT, and the
/// amounts and windows below.
contract L2Campaign is Script, NotarySigner {
    bytes32 internal constant POLICY_R = keccak256("pprev.rental.register");
    bytes32 internal constant POLICY_A = keccak256("pprev.rental.apply");
    bytes32 internal constant POLICY_S = keccak256("pprev.rental.settle");

    address internal owner;
    address internal applicant;
    string internal steps;
    uint256 internal stepCount;

    function env(string memory name) internal view returns (uint256) {
        return vm.envUint(name);
    }

    function load() internal {
        owner = vm.envAddress("OWNER");
        applicant = vm.envAddress("APPLICANT");
    }

    function deployment(string memory key) internal view returns (PPREV) {
        return PPREV(vm.parseJsonAddress(vm.readFile(vm.envString("STATE")), key));
    }

    // ------------------------------------------------------------------ phases

    function deploy() external {
        load();
        uint64 n = vm.getNonce(owner);
        address verifier = vm.computeCreateAddress(owner, n + 1);
        address pprevA = vm.computeCreateAddress(owner, n + 2);
        address pprevB = vm.computeCreateAddress(owner, n + 3);
        step("fund-applicant", "owner", applicant, env("APPLICANT_FUNDING"), "", address(0));
        step(
            "deploy-verifier",
            "owner",
            address(0),
            0,
            abi.encodePacked(type(EcdsaNotaryVerifier).creationCode, abi.encode(vm.addr(NOTARY_PK))),
            verifier
        );
        step("deploy-pprev-A", "owner", address(0), 0, pprevInitcode(verifier, env("TAU_LOCK_A")), pprevA);
        step("deploy-pprev-B", "owner", address(0), 0, pprevInitcode(verifier, env("TAU_LOCK_B")), pprevB);
        bytes memory policy = abi.encodeCall(
            PPREV.registerPolicy,
            (POLICY_R, POLICY_A, POLICY_S, env("REQ_ESCROW"), env("MIN_COLLATERAL"), env("MAX_COLLATERAL"))
        );
        step("register-policy-A", "owner", pprevA, 0, policy, address(0));
        step("register-policy-B", "owner", pprevB, 0, policy, address(0));

        string memory o = "state";
        vm.serializeAddress(o, "verifier", verifier);
        vm.serializeAddress(o, "pprevA", pprevA);
        vm.writeJson(vm.serializeAddress(o, "pprevB", pprevB), vm.envString("STATE"));
        write();
    }

    function registers() external {
        load();
        PPREV a = deployment(".pprevA");
        for (uint256 i = 1; i <= env("REGISTER_COUNT"); i++) {
            registerStep(string.concat("register-A-", vm.toString(i)), a, i);
        }
        registerStep("register-B-1", deployment(".pprevB"), 1);
        write();
    }

    function applies() external {
        load();
        PPREV a = deployment(".pprevA");
        applyStep("apply-A-1", a, 1);
        applyStep("apply-A-2", a, 2);
        applyStep("apply-B-1", deployment(".pprevB"), 1);
        step("cancel-A-3", "owner", address(a), 0, abi.encodeCall(PPREV.cancel, (3)), address(0));
        write();
    }

    function engages() external {
        load();
        PPREV a = deployment(".pprevA");
        step("engage-A-1", "owner", address(a), 0, abi.encodeCall(PPREV.engage, (1, 1)), address(0));
        step("engage-B-1", "owner", address(deployment(".pprevB")), 0, abi.encodeCall(PPREV.engage, (1, 1)), address(0));
        step("reclaim-A-2", "applicant", address(a), 0, abi.encodeCall(PPREV.reclaim, (2)), address(0));
        write();
    }

    function settles() external {
        load();
        PPREV a = deployment(".pprevA");
        signingTarget = address(a);
        (,,,, bytes32 cB) = a.applications(1);
        (, uint256 expiresAt,) = a.engagements(1);
        XS memory x = XS({
            engId: 1,
            txId: 1,
            cTx: commitment(a, 1),
            txData: txData(),
            cB: cB,
            expiresAt: expiresAt,
            policyId: POLICY_S,
            submitter: owner,
            eta: derive("eta-S", a, 1),
            tAtt: uint64(block.timestamp)
        });
        step(
            "settle-A-1",
            "owner",
            address(a),
            0,
            abi.encodeCall(PPREV.settle, (1, x.txData, salt(a, 1), signS(x), x.eta, x.tAtt)),
            address(0)
        );
        write();
    }

    function expires() external {
        load();
        PPREV b = deployment(".pprevB");
        (, uint256 expiresAt,) = b.engagements(1);
        // The sender waits until a block is later than expiresAt (E(c)); STEPS_OUT records when.
        step("expire-B-1", "applicant", address(b), 0, abi.encodeCall(PPREV.expire, (1)), address(0));
        vm.writeFile(
            vm.envString("STEPS_OUT"),
            string.concat('{"notBefore":', vm.toString(expiresAt + 1), ',"steps":[', steps, "]}")
        );
    }

    // ------------------------------------------------------------------ transactions

    function pprevInitcode(address verifier, uint256 tauLock) internal view returns (bytes memory) {
        return abi.encodePacked(
            type(PPREV).creationCode,
            abi.encode(owner, INotaryVerifier(verifier), env("DELTA"), tauLock, env("MAX_EXPIRATIONS"), env("RHO"))
        );
    }

    function registerStep(string memory label, PPREV pprev, uint256 i) internal {
        signingTarget = address(pprev);
        XR memory x = XR({
            cTx: commitment(pprev, i),
            txData: txData(),
            policyId: POLICY_R,
            submitter: owner,
            eta: derive("eta-R", pprev, i),
            tAtt: uint64(block.timestamp)
        });
        bytes memory data =
            abi.encodeCall(PPREV.register, (x.cTx, x.txData, POLICY_R, salt(pprev, i), signR(x), x.eta, x.tAtt));
        step(label, "owner", address(pprev), env("COLLATERAL"), data, address(0));
    }

    function applyStep(string memory label, PPREV pprev, uint256 txId) internal {
        signingTarget = address(pprev);
        XA memory x = XA({
            txId: txId,
            cTx: commitment(pprev, txId),
            txData: txData(),
            cB: keccak256(abi.encode("c_B", applicant)),
            policyId: POLICY_A,
            submitter: applicant,
            eta: derive("eta-A", pprev, txId),
            tAtt: uint64(block.timestamp)
        });
        bytes memory data =
            abi.encodeCall(PPREV.applyFor, (txId, x.txData, salt(pprev, txId), x.cB, signA(x), x.eta, x.tAtt));
        step(label, "applicant", address(pprev), env("DEPOSIT"), data, address(0));
    }

    function txData() internal view returns (TxData memory) {
        return TxData({propertyId: bytes32("TR-06-CANKAYA-000123"), amount: env("AMOUNT"), settlementShare: 0});
    }

    function derive(string memory tag, PPREV pprev, uint256 i) internal view returns (bytes32) {
        return keccak256(abi.encode(tag, block.chainid, address(pprev), i));
    }

    function salt(PPREV pprev, uint256 i) internal view returns (bytes32) {
        return derive("r", pprev, i);
    }

    function commitment(PPREV pprev, uint256 i) internal view returns (bytes32) {
        return keccak256(abi.encode(txData(), POLICY_R, salt(pprev, i)));
    }

    // ------------------------------------------------------------------ output

    function step(
        string memory label,
        string memory from,
        address to,
        uint256 value,
        bytes memory data,
        address expectCreate
    ) internal {
        string memory s = string.concat(
            '{"label":"',
            label,
            '","from":"',
            from,
            '","to":',
            to == address(0) ? "null" : string.concat('"', vm.toString(to), '"'),
            ',"value":"',
            vm.toString(value),
            '","data":"',
            vm.toString(data),
            '","expectCreate":',
            expectCreate == address(0) ? "null" : string.concat('"', vm.toString(expectCreate), '"'),
            "}"
        );
        steps = stepCount == 0 ? s : string.concat(steps, ",", s);
        stepCount++;
    }

    function write() internal {
        vm.writeFile(vm.envString("STEPS_OUT"), string.concat('{"steps":[', steps, "]}"));
    }
}

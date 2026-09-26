// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Vm} from "forge-std/Vm.sol";
import {PPREV} from "../src/PPREV.sol";
import {INotaryVerifier} from "../src/interfaces/INotaryVerifier.sol";
import {Fixture, RegisterCall, ApplyCall, SettleCall, Flow} from "../test/utils/Fixture.sol";
import {AcceptAllVerifier} from "../test/mocks/AcceptAllVerifier.sol";

/// @dev Measures one complete cold call to a verifier from inside a contract frame.
contract VerifyProbe {
    function probe(INotaryVerifier verifier, bytes32 digest, bytes calldata sigma)
        external
        view
        returns (uint256 used)
    {
        uint256 before = gasleft();
        verifier.verify(digest, sigma);
        used = before - gasleft();
    }
}

/// @notice Execution gas of each of the seven algorithms (Section VII-A), its storage decomposition
/// from a recorded state diff, the marginal cost of ECDSA verification against an accept-all
/// verifier, and the verifier call costs. Writes JSON to the file named by GAS_OUT.
///
/// Method. Each operation runs on a fresh deployment after only the operations it requires. forge
/// runs a pranked top-level call of a script as a transaction of its own, so the caller and the
/// contract are warm and every other account (the verifier, payees) starts cold (EIP-2929); the
/// contract, the verifier, and the payees are also cooled explicitly before the call. `vm.lastCallGas`
/// then reports transaction gas before the refund: 21,000 intrinsic gas, calldata gas, and execution
/// gas. Execution gas is that total minus 21,000 and the EIP-2028 calldata gas of the call; the
/// refund is reported separately and not netted. The call is then replayed from a snapshot with
/// state-diff recording; each storage slot is classified by its first previous value and its writes:
/// initialised (zero to non-zero), updated (non-zero, written), or read only; every access after a
/// slot's first is a warm re-access. The verifier costs are frame-level (calls without prank).
/// Usage: GAS_OUT=../target/measure/gas.json forge script script/MeasureGas.s.sol
contract MeasureGas is Fixture {
    enum Op {
        Register,
        Apply,
        Engage,
        Settle,
        Expire,
        Reclaim,
        Cancel
    }

    struct Prepared {
        address sender;
        uint256 value;
        bytes data;
        address[] payees;
    }

    uint256 internal constant TX_INTRINSIC = 21_000;

    struct StorageCounts {
        uint256 initialised;
        uint256 updated;
        uint256 readOnly;
        uint256 warmReaccesses;
        uint256 accesses;
    }

    bool internal acceptAll;
    address internal verifierInUse;

    function deploy(INotaryVerifier v) internal override returns (PPREV) {
        if (acceptAll) v = INotaryVerifier(address(new AcceptAllVerifier()));
        verifierInUse = address(v);
        return super.deploy(v);
    }

    function run() external {
        string memory ops = "{";
        for (uint256 i = 0; i <= uint256(Op.Cancel); i++) {
            Op op = Op(i);
            if (i > 0) ops = string.concat(ops, ",");
            ops = string.concat(ops, field(opName(op), measureOp(op)));
        }
        ops = string.concat(ops, "}");
        string memory json = string.concat("{", field("operations", ops), ",", field("verifier", verifierCosts()), "}");
        vm.writeFile(vm.envString("GAS_OUT"), json);
    }

    // ------------------------------------------------------------------ per operation

    function measureOp(Op op) internal returns (string memory) {
        Prepared memory p = prepare(op);
        uint256 snapshot = vm.snapshotState();
        (uint256 gasUsed, int256 refund) = measure(p);
        vm.revertToStateAndDelete(snapshot);
        (uint256 recordedGas, StorageCounts memory s) = record(p);

        string memory json = string.concat("{", gasJson(gasUsed, calldataCost(p.data)), ",");
        json = string.concat(json, field("refund", vm.toString(refund)), ",");
        json = string.concat(json, field("sender", q(vm.toString(p.sender))), ",");
        json = string.concat(json, num("calldataBytes", p.data.length), ",");
        json = string.concat(json, field("storage", storageJson(s)), ",");
        json = string.concat(json, num("recordedTransactionGas", recordedGas));
        if (op == Op.Register || op == Op.Apply || op == Op.Settle) {
            acceptAll = true;
            (uint256 baseline,) = measure(prepare(op));
            acceptAll = false;
            json = string.concat(
                json,
                ",",
                num("acceptAllGas", baseline),
                ",",
                field("ecdsaMarginal", vm.toString(int256(gasUsed) - int256(baseline)))
            );
        }
        return string.concat(json, "}");
    }

    /// @dev A fresh deployment with only the operations `op` requires, and the call to measure.
    function prepare(Op op) internal returns (Prepared memory p) {
        setUp();
        if (op == Op.Register) {
            RegisterCall memory c = registerCall();
            p = call(
                c.caller,
                c.collateral,
                abi.encodeCall(PPREV.register, (c.cTx, c.txData, c.policyIdR, c.r, signR(xROf(c)), c.eta, c.tAtt)),
                none()
            );
        } else if (op == Op.Apply) {
            Flow memory f = flowRegistered();
            ApplyCall memory c = applyCall(f, applicant);
            p = call(
                c.caller,
                c.deposit,
                abi.encodeCall(PPREV.applyFor, (c.txId, c.txData, c.r, c.cB, signA(xAOf(c)), c.eta, c.tAtt)),
                none()
            );
        } else if (op == Op.Engage) {
            Flow memory f = flowApplied();
            p = call(owner, 0, abi.encodeCall(PPREV.engage, (f.txId, f.appId)), none());
        } else if (op == Op.Settle) {
            Flow memory f = flowEngaged();
            SettleCall memory c = settleCall(f);
            p = call(
                c.caller,
                0,
                abi.encodeCall(PPREV.settle, (c.engId, c.txData, c.r, signS(xSOf(c)), c.eta, c.tAtt)),
                one(applicant)
            );
        } else if (op == Op.Expire) {
            // The applicant calls: it is the payee (deposit plus compensation).
            Flow memory f = flowEngaged();
            vm.warp(f.expiresAt + 1);
            p = call(applicant, 0, abi.encodeCall(PPREV.expire, (f.engId)), none());
        } else if (op == Op.Reclaim) {
            Flow memory f = flowApplied();
            p = call(applicant, 0, abi.encodeCall(PPREV.reclaim, (f.appId)), none());
        } else {
            Flow memory f = flowRegistered();
            p = call(owner, 0, abi.encodeCall(PPREV.cancel, (f.txId)), none());
        }
    }

    function cool(Prepared memory p) internal {
        vm.cool(address(pprev));
        vm.cool(verifierInUse);
        for (uint256 i = 0; i < p.payees.length; i++) {
            vm.cool(p.payees[i]);
        }
    }

    function execute(Prepared memory p) internal returns (Vm.Gas memory g) {
        vm.prank(p.sender);
        (bool ok,) = address(pprev).call{value: p.value}(p.data);
        require(ok, "measured call reverted");
        g = vm.lastCallGas();
    }

    function measure(Prepared memory p) internal returns (uint256 gasUsed, int256 refund) {
        cool(p);
        Vm.Gas memory g = execute(p);
        return (g.gasTotalUsed, g.gasRefunded);
    }

    /// @dev Runs the call with state-diff recording; the caller restores the pre-call state first.
    function record(Prepared memory p) internal returns (uint256 gasUsed, StorageCounts memory s) {
        cool(p);
        vm.startStateDiffRecording();
        Vm.Gas memory g = execute(p);
        Vm.AccountAccess[] memory accesses = vm.stopAndReturnStateDiff();
        return (g.gasTotalUsed, classify(accesses));
    }

    function classify(Vm.AccountAccess[] memory accesses) internal pure returns (StorageCounts memory s) {
        uint256 total;
        for (uint256 i = 0; i < accesses.length; i++) {
            total += accesses[i].storageAccesses.length;
        }
        address[] memory accounts = new address[](total);
        bytes32[] memory slots = new bytes32[](total);
        bytes32[] memory firstPrevious = new bytes32[](total);
        bool[] memory written = new bool[](total);
        bool[] memory becameNonZero = new bool[](total);
        uint256 distinct;
        for (uint256 i = 0; i < accesses.length; i++) {
            Vm.StorageAccess[] memory sa = accesses[i].storageAccesses;
            for (uint256 j = 0; j < sa.length; j++) {
                if (sa[j].reverted) continue;
                s.accesses++;
                uint256 k = 0;
                while (k < distinct && !(accounts[k] == sa[j].account && slots[k] == sa[j].slot)) k++;
                if (k == distinct) {
                    accounts[k] = sa[j].account;
                    slots[k] = sa[j].slot;
                    firstPrevious[k] = sa[j].previousValue;
                    distinct++;
                } else {
                    s.warmReaccesses++;
                }
                if (sa[j].isWrite) {
                    written[k] = true;
                    if (sa[j].newValue != bytes32(0)) becameNonZero[k] = true;
                }
            }
        }
        for (uint256 k = 0; k < distinct; k++) {
            if (!written[k]) s.readOnly++;
            else if (firstPrevious[k] == bytes32(0) && becameNonZero[k]) s.initialised++;
            else if (firstPrevious[k] != bytes32(0)) s.updated++;
        }
    }

    // ------------------------------------------------------------------ verifier

    function verifierCosts() internal returns (string memory) {
        setUp();
        RegisterCall memory c = registerCall();
        bytes32 d = digest(structHashR(xROf(c)));
        bytes memory sigma = signR(xROf(c));
        AcceptAllVerifier acceptAllVerifier = new AcceptAllVerifier();
        VerifyProbe probe = new VerifyProbe();

        vm.cool(address(verifier));
        require(verifier.verify(d, sigma), "signature rejected");
        uint256 ecdsaFrame = vm.lastCallGas().gasTotalUsed;
        vm.cool(address(acceptAllVerifier));
        acceptAllVerifier.verify(d, sigma);
        uint256 acceptAllFrame = vm.lastCallGas().gasTotalUsed;
        vm.cool(address(verifier));
        uint256 ecdsaColdCall = probe.probe(INotaryVerifier(address(verifier)), d, sigma);
        vm.cool(address(acceptAllVerifier));
        uint256 acceptAllColdCall = probe.probe(INotaryVerifier(address(acceptAllVerifier)), d, sigma);
        return string.concat(
            "{",
            num("ecdsaFrame", ecdsaFrame),
            ",",
            num("acceptAllFrame", acceptAllFrame),
            ",",
            num("ecdsaColdCallFromContract", ecdsaColdCall),
            ",",
            num("acceptAllColdCallFromContract", acceptAllColdCall),
            "}"
        );
    }

    // ------------------------------------------------------------------ helpers

    function call(address sender, uint256 value, bytes memory data, address[] memory payees)
        internal
        pure
        returns (Prepared memory p)
    {
        p.sender = sender;
        p.value = value;
        p.data = data;
        p.payees = payees;
    }

    /// @dev EIP-2028: 4 gas per zero byte, 16 per non-zero byte.
    function calldataCost(bytes memory data) internal pure returns (uint256 cost) {
        for (uint256 i = 0; i < data.length; i++) {
            cost += data[i] == 0 ? 4 : 16;
        }
    }

    function none() internal pure returns (address[] memory) {
        return new address[](0);
    }

    function one(address a) internal pure returns (address[] memory list) {
        list = new address[](1);
        list[0] = a;
    }

    function opName(Op op) internal pure returns (string memory) {
        string[7] memory names = ["Register", "Apply", "Engage", "Settle", "Expire", "Reclaim", "Cancel"];
        return names[uint256(op)];
    }

    function gasJson(uint256 transactionGas, uint256 calldataGas) internal pure returns (string memory) {
        return string.concat(
            num("executionGas", transactionGas - TX_INTRINSIC - calldataGas),
            ",",
            num("transactionGas", transactionGas),
            ",",
            num("intrinsicGas", TX_INTRINSIC),
            ",",
            num("calldataGas", calldataGas)
        );
    }

    function storageJson(StorageCounts memory s) internal pure returns (string memory) {
        return string.concat(
            "{",
            num("initialised", s.initialised),
            ",",
            num("updated", s.updated),
            ",",
            num("readOnly", s.readOnly),
            ",",
            num("warmReaccesses", s.warmReaccesses),
            ",",
            num("accesses", s.accesses),
            "}"
        );
    }

    function q(string memory s) internal pure returns (string memory) {
        return string.concat('"', s, '"');
    }

    function field(string memory name, string memory value) internal pure returns (string memory) {
        return string.concat('"', name, '":', value);
    }

    function num(string memory name, uint256 value) internal pure returns (string memory) {
        return field(name, vm.toString(value));
    }
}

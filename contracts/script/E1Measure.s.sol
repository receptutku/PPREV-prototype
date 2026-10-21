// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Script, console} from "forge-std/Script.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {Groth16Verifier as PhiRGroth16} from "pprev-circuits/Groth16Verifier.sol";
import {Groth16Verifier as PhiAGroth16} from "pprev-circuits/phi_a/Groth16Verifier.sol";
import {Groth16Verifier as PhiSGroth16} from "pprev-circuits/phi_s/Groth16Verifier.sol";
import {IntegratedRegisterVerifier, IPhiRVerifier} from "../src/baseline/IntegratedRegisterVerifier.sol";
import {IntegratedApplyVerifier, IPhiAVerifier} from "../src/baseline/IntegratedApplyVerifier.sol";
import {IntegratedSettleVerifier, IPhiSVerifier} from "../src/baseline/IntegratedSettleVerifier.sol";
import {E1Fixtures} from "../test/baseline/E1Fixtures.sol";

/// @notice Deploys the exported verifier and the integrated baseline of one phase (E1_PHASE:
/// register, apply, or settle) with the configuration of its fixture, and writes the calldata of
/// `verify` for the fixture's submission, and of one with a changed submitter, to
/// ../target/measure/e1-<phase>-*.txt. Used by script/measure_e1.sh. Environment: DEPLOYER_KEY.
contract E1Measure is Script, E1Fixtures {
    using stdJson for string;

    function run() external {
        string memory phase = vm.envString("E1_PHASE");
        string memory fx = readFixture(phase);
        bytes32 p = keccak256(bytes(phase));
        address deployed;
        address groth16;
        bytes memory valid;
        bytes memory tampered;
        vm.startBroadcast(vm.envUint("DEPLOYER_KEY"));
        if (p == keccak256("register")) {
            groth16 = address(new PhiRGroth16());
            IntegratedRegisterVerifier b = new IntegratedRegisterVerifier(baseConfig(fx), IPhiRVerifier(groth16));
            deployed = address(b);
            IntegratedRegisterVerifier.Submission memory s = registerSubmission(fx);
            valid = abi.encodeCall(b.verify, (s));
            s.submitter = address(0xBEEF);
            tampered = abi.encodeCall(b.verify, (s));
        } else if (p == keccak256("apply")) {
            groth16 = address(new PhiAGroth16());
            IntegratedApplyVerifier b = new IntegratedApplyVerifier(
                baseConfig(fx), IPhiAVerifier(groth16), keccak256(bytes(fx.readString(".requestLine")))
            );
            deployed = address(b);
            IntegratedApplyVerifier.Submission memory s = applySubmission(fx);
            valid = abi.encodeCall(b.verify, (s));
            s.submitter = address(0xBEEF);
            tampered = abi.encodeCall(b.verify, (s));
        } else if (p == keccak256("settle")) {
            groth16 = address(new PhiSGroth16());
            IntegratedSettleVerifier b = new IntegratedSettleVerifier(
                baseConfig(fx),
                IPhiSVerifier(groth16),
                uint64(fx.readUint(".tauLock")),
                int64(fx.readInt(".utcOffsetSecs"))
            );
            deployed = address(b);
            IntegratedSettleVerifier.Submission memory s = settleSubmission(fx);
            valid = abi.encodeCall(b.verify, (s));
            s.submitter = address(0xBEEF);
            tampered = abi.encodeCall(b.verify, (s));
        } else {
            revert("E1_PHASE is register, apply, or settle");
        }
        vm.stopBroadcast();
        vm.writeFile(string.concat("../target/measure/e1-", phase, "-verify-calldata.txt"), vm.toString(valid));
        vm.writeFile(string.concat("../target/measure/e1-", phase, "-tampered-calldata.txt"), vm.toString(tampered));
        vm.writeFile(
            string.concat("../target/measure/e1-", phase, "-addresses.txt"),
            string.concat(vm.toString(deployed), " ", vm.toString(groth16))
        );
        console.log("baseline", deployed, "groth16", groth16);
    }
}

// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Script, console} from "forge-std/Script.sol";
import {PPREV} from "../src/PPREV.sol";
import {INotaryVerifier} from "../src/interfaces/INotaryVerifier.sol";
import {EcdsaNotaryVerifier} from "../src/verifiers/EcdsaNotaryVerifier.sol";

/// @notice Deploys EcdsaNotaryVerifier(vk_notary) and PPREV with the D18 parameters, and registers the
/// policy bundle of a policy file. The deployer is the operator.
/// Environment: DEPLOYER_KEY (private key), VK_NOTARY (address of sk_notary), PPREV_POLICY (policy
/// file, default ../policies/rental-v1.json).
/// Usage: forge script script/Deploy.s.sol --rpc-url <url> --broadcast
contract Deploy is Script {
    // D18, as in test/utils/Fixture.sol.
    uint256 internal constant DELTA = 300;
    uint256 internal constant TAU_LOCK = 14 days;
    uint256 internal constant MAX_EXPIRATIONS = 3;
    uint256 internal constant RHO = 5000;

    function run() external returns (EcdsaNotaryVerifier verifier, PPREV pprev) {
        uint256 deployerKey = vm.envUint("DEPLOYER_KEY");
        address vkNotary = vm.envAddress("VK_NOTARY");
        string memory policy = vm.readFile(vm.envOr("PPREV_POLICY", string("../policies/rental-v1.json")));

        // policyID_psi = keccak256(label), as pprev-types derives it (offchain/crates/pprev-types/src/policy.rs).
        bytes32 policyIdR = keccak256(bytes(vm.parseJsonString(policy, ".labels.register")));
        bytes32 policyIdA = keccak256(bytes(vm.parseJsonString(policy, ".labels.apply")));
        bytes32 policyIdS = keccak256(bytes(vm.parseJsonString(policy, ".labels.settle")));
        uint256 reqEscrow = vm.parseUint(vm.parseJsonString(policy, ".reqEscrowWei"));
        uint256 minCollateral = vm.parseUint(vm.parseJsonString(policy, ".minCollateralWei"));
        uint256 maxCollateral = vm.parseUint(vm.parseJsonString(policy, ".maxCollateralWei"));

        vm.startBroadcast(deployerKey);
        verifier = new EcdsaNotaryVerifier(vkNotary);
        pprev =
            new PPREV(vm.addr(deployerKey), INotaryVerifier(address(verifier)), DELTA, TAU_LOCK, MAX_EXPIRATIONS, RHO);
        pprev.registerPolicy(policyIdR, policyIdA, policyIdS, reqEscrow, minCollateral, maxCollateral);
        vm.stopBroadcast();

        console.log("EcdsaNotaryVerifier", address(verifier));
        console.log("PPREV", address(pprev));
    }
}

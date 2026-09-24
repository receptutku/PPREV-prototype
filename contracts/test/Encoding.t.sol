// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Fixture} from "./utils/Fixture.sol";
import {PPREVHarness} from "./utils/PPREVHarness.sol";
import {TypedDataJson} from "./utils/TypedDataJson.sol";
import {SampleStatements} from "./utils/SampleStatements.sol";
import {XR, XA, XS} from "./utils/NotarySigner.sol";
import {PPREV} from "../src/PPREV.sol";
import {PPREVEncoding} from "../src/PPREVEncoding.sol";
import {INotaryVerifier} from "../src/interfaces/INotaryVerifier.sol";
import {TxData} from "../src/PPREVTypes.sol";

/// @notice The contract's C_tx and EIP-712 digests agree with two independent implementations: the
/// test signer (written from Table III) and Foundry's EIP-712 encoder. The golden vectors written by
/// script/GenVectors.s.sol still match.
contract EncodingTest is Fixture, TypedDataJson {
    PPREVHarness internal harness;

    function deploy(INotaryVerifier v) internal override returns (PPREV) {
        harness = new PPREVHarness(operator, v, DELTA, TAU_LOCK, MAX_EXPIRATIONS, RHO);
        return harness;
    }

    function contractDigestR(XR memory x) internal view returns (bytes32) {
        PPREVEncoding.RegisterStatement memory s = PPREVEncoding.RegisterStatement({
            cTx: x.cTx,
            txDataHash: harness.exposedHashTxData(x.txData),
            policyId: x.policyId,
            submitter: x.submitter,
            eta: x.eta,
            tAtt: x.tAtt
        });
        return harness.exposedHashTypedData(harness.exposedHashRegister(s));
    }

    function contractDigestA(XA memory x) internal view returns (bytes32) {
        PPREVEncoding.ApplyStatement memory s = PPREVEncoding.ApplyStatement({
            txId: x.txId,
            cTx: x.cTx,
            txDataHash: harness.exposedHashTxData(x.txData),
            cB: x.cB,
            policyId: x.policyId,
            submitter: x.submitter,
            eta: x.eta,
            tAtt: x.tAtt
        });
        return harness.exposedHashTypedData(harness.exposedHashApply(s));
    }

    function contractDigestS(XS memory x) internal view returns (bytes32) {
        PPREVEncoding.SettleStatement memory s;
        s.engId = x.engId;
        s.txId = x.txId;
        s.cTx = x.cTx;
        s.txDataHash = harness.exposedHashTxData(x.txData);
        s.cB = x.cB;
        s.expiresAt = x.expiresAt;
        s.policyId = x.policyId;
        s.submitter = x.submitter;
        s.eta = x.eta;
        s.tAtt = x.tAtt;
        return harness.exposedHashTypedData(harness.exposedHashSettle(s));
    }

    // ------------------------------------------------------------------ three-way agreement

    function testFuzz_Encoding_registerDigestAgrees(XR memory x) public view {
        bytes32 viaContract = contractDigestR(x);
        assertEq(viaContract, digest(structHashR(x)), "test signer");
        assertEq(viaContract, vm.eip712HashTypedData(typedDataR(x, vm.getChainId(), address(pprev))), "Foundry");
    }

    function testFuzz_Encoding_applyDigestAgrees(XA memory x) public view {
        bytes32 viaContract = contractDigestA(x);
        assertEq(viaContract, digest(structHashA(x)), "test signer");
        assertEq(viaContract, vm.eip712HashTypedData(typedDataA(x, vm.getChainId(), address(pprev))), "Foundry");
    }

    function testFuzz_Encoding_settleDigestAgrees(XS memory x) public view {
        bytes32 viaContract = contractDigestS(x);
        assertEq(viaContract, digest(structHashS(x)), "test signer");
        assertEq(viaContract, vm.eip712HashTypedData(typedDataS(x, vm.getChainId(), address(pprev))), "Foundry");
    }

    function testFuzz_Encoding_commitmentIsConcatenation(TxData memory d, bytes32 policyIdR, bytes32 r) public view {
        bytes32 expected = keccak256(abi.encodePacked(d.propertyId, d.amount, d.settlementShare, policyIdR, r));
        assertEq(harness.exposedCommitment(d, policyIdR, r), expected);
    }

    function test_Encoding_domainSeparatorMatchesEip712() public view {
        assertEq(pprev.domainSeparator(), domainSeparatorFor(vm.getChainId(), address(pprev)));
    }

    // ------------------------------------------------------------------ golden vectors

    function test_Encoding_goldenVectorsMatch() public view {
        string memory json = vm.readFile("../test-vectors/eip712.json");
        uint256 chainId = vm.parseUint(vm.parseJsonString(json, ".domain.chainId"));
        address vc = vm.parseJsonAddress(json, ".domain.verifyingContract");

        assertEq(
            harness.exposedCommitment(SampleStatements.txData(), SampleStatements.POLICY_R, SampleStatements.SALT),
            vm.parseJsonBytes32(json, ".commitment.cTx"),
            "C_tx"
        );

        XR memory xR = SampleStatements.register();
        assertEq(structHashR(xR), vm.parseJsonBytes32(json, ".register.structHash"), "register struct hash");
        assertEq(digestFor(structHashR(xR), chainId, vc), vm.parseJsonBytes32(json, ".register.digest"), "register");

        XA memory xA = SampleStatements.apply_();
        assertEq(structHashA(xA), vm.parseJsonBytes32(json, ".apply.structHash"), "apply struct hash");
        assertEq(digestFor(structHashA(xA), chainId, vc), vm.parseJsonBytes32(json, ".apply.digest"), "apply");

        XS memory xS = SampleStatements.settle();
        assertEq(structHashS(xS), vm.parseJsonBytes32(json, ".settle.structHash"), "settle struct hash");
        assertEq(digestFor(structHashS(xS), chainId, vc), vm.parseJsonBytes32(json, ".settle.digest"), "settle");

        // The contract's struct hashes for the vector statements equal the recorded ones.
        assertEq(
            harness.exposedHashTypedData(vm.parseJsonBytes32(json, ".register.structHash")),
            contractDigestR(xR),
            "contract register"
        );
        assertEq(
            harness.exposedHashTypedData(vm.parseJsonBytes32(json, ".apply.structHash")),
            contractDigestA(xA),
            "contract apply"
        );
        assertEq(
            harness.exposedHashTypedData(vm.parseJsonBytes32(json, ".settle.structHash")),
            contractDigestS(xS),
            "contract settle"
        );
    }
}

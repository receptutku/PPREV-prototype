// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {Groth16Verifier} from "pprev-circuits/Groth16Verifier.sol";
import {IntegratedVerifierBase} from "../../src/baseline/IntegratedVerifierBase.sol";
import {IntegratedRegisterVerifier, IPhiRVerifier} from "../../src/baseline/IntegratedRegisterVerifier.sol";
import {E1Fixtures} from "./E1Fixtures.sol";

/// @notice The integrated on-chain verification baseline for Register on a real attestation, and the
/// rejection of every altered part. The attestation checks are common to the three phases
/// (IntegratedVerifierBase); this suite exercises them, the Apply and Settle suites their own parts.
contract IntegratedRegisterVerifierTest is Test, E1Fixtures {
    using stdJson for string;

    string internal fx;
    IntegratedRegisterVerifier internal baseline;
    /// Test-only key of the identity attestor (the fixture generator's IDENTITY_KEY).
    uint256 internal constant IDENTITY_KEY = 0x0909090909090909090909090909090909090909090909090909090909090909;

    function setUp() public {
        fx = readFixture("register");
        Groth16Verifier phiR = new Groth16Verifier();
        deployCodeTo(
            "IntegratedRegisterVerifier.sol:IntegratedRegisterVerifier",
            abi.encode(baseConfig(fx), IPhiRVerifier(address(phiR))),
            fx.readAddress(".baseline")
        );
        baseline = IntegratedRegisterVerifier(fx.readAddress(".baseline"));
        vm.chainId(fx.readUint(".chainId"));
        vm.warp(fx.readUint(".tAtt") + 10);
    }

    function _sub() internal view returns (IntegratedRegisterVerifier.Submission memory) {
        return registerSubmission(fx);
    }

    function _rejects(IntegratedRegisterVerifier.Submission memory s, bytes4 selector) internal {
        vm.expectRevert(selector);
        baseline.verify(s);
    }

    function _identity(bytes memory header, bytes32 serverNameHash, bytes32 policyId)
        internal
        view
        returns (bytes memory)
    {
        bytes32 digest = keccak256(
            abi.encode(
                keccak256("PPREV.identity.v1"),
                keccak256(header),
                fx.readAddress(".attestation.signer"),
                serverNameHash,
                policyId
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(IDENTITY_KEY, digest);
        return abi.encodePacked(r, s, v);
    }

    function test_accepts_the_real_submission() public view {
        assertTrue(baseline.verify(_sub()));
    }

    // Header and signatures ---------------------------------------------------------------------

    function test_rejects_a_header_with_a_trailing_byte() public {
        IntegratedRegisterVerifier.Submission memory s = _sub();
        s.att.header = abi.encodePacked(s.att.header, bytes1(0));
        _rejects(s, IntegratedVerifierBase.BadHeader.selector);
    }

    function test_rejects_an_unsupported_hash_algorithm() public {
        IntegratedRegisterVerifier.Submission memory s = _sub();
        s.att.header[20] = 0x02; // BLAKE3
        _rejects(s, IntegratedVerifierBase.BadHeader.selector);
    }

    function test_rejects_another_version() public {
        IntegratedRegisterVerifier.Submission memory s = _sub();
        s.att.header[16] = 0x01;
        _rejects(s, IntegratedVerifierBase.BadHeader.selector);
    }

    function test_rejects_a_header_the_notary_did_not_sign() public {
        IntegratedRegisterVerifier.Submission memory s = _sub();
        s.att.header[0] = bytes1(uint8(s.att.header[0]) ^ 1);
        _rejects(s, IntegratedVerifierBase.BadSignature.selector);
    }

    function test_rejects_a_malleable_signature() public {
        IntegratedRegisterVerifier.Submission memory s = _sub();
        uint256 n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        bytes32 r;
        bytes32 sv;
        bytes memory sig = s.att.signature;
        assembly {
            r := mload(add(sig, 32))
            sv := mload(add(sig, 64))
        }
        uint8 v = uint8(sig[64]) < 27 ? uint8(sig[64]) + 27 : uint8(sig[64]);
        s.att.signature = abi.encodePacked(r, bytes32(n - uint256(sv)), v == 27 ? uint8(28) : uint8(27));
        _rejects(s, IntegratedVerifierBase.BadSignature.selector);
    }

    function test_rejects_an_identity_signature_for_another_server() public {
        IntegratedRegisterVerifier.Submission memory s = _sub();
        s.att.identitySignature = _identity(s.att.header, keccak256("other.pprev.test"), s.policyId);
        _rejects(s, IntegratedVerifierBase.BadIdentity.selector);
    }

    function test_rejects_an_identity_signature_transplanted_from_another_header() public {
        IntegratedRegisterVerifier.Submission memory s = _sub();
        bytes memory other = abi.encodePacked(s.att.header);
        other[0] = bytes1(uint8(other[0]) ^ 1);
        s.att.identitySignature = _identity(other, keccak256(bytes(fx.readString(".serverName"))), s.policyId);
        _rejects(s, IntegratedVerifierBase.BadIdentity.selector);
    }

    function test_rejects_another_policy() public {
        IntegratedRegisterVerifier.Submission memory s = _sub();
        s.policyId = keccak256("pprev.rental.apply");
        _rejects(s, IntegratedVerifierBase.UnknownPolicy.selector);
    }

    function test_rejects_another_verifying_key_field() public {
        IntegratedRegisterVerifier.Submission memory s = _sub();
        s.att.verifyingKey[3] = bytes1(uint8(s.att.verifyingKey[3]) ^ 1);
        _rejects(s, IntegratedVerifierBase.BadVerifyingKey.selector);
    }

    // Connection and time ------------------------------------------------------------------------

    function test_rejects_another_received_length() public {
        IntegratedRegisterVerifier.Submission memory s = _sub();
        s.att.connectionInfo[13] = bytes1(uint8(s.att.connectionInfo[13]) ^ 1);
        _rejects(s, IntegratedVerifierBase.BadConnectionInfo.selector);
    }

    function test_rejects_tls13() public {
        IntegratedRegisterVerifier.Submission memory s = _sub();
        s.att.connectionInfo[8] = 0x01;
        _rejects(s, IntegratedVerifierBase.BadConnectionInfo.selector);
    }

    function test_rejects_a_submission_after_delta() public {
        vm.warp(fx.readUint(".tAtt") + 301);
        _rejects(_sub(), IntegratedVerifierBase.NotFresh.selector);
    }

    function test_rejects_another_attestation_time() public {
        IntegratedRegisterVerifier.Submission memory s = _sub();
        s.att.tAtt -= 1; // within the window, but not the attested t_att: the extension leaf differs
        _rejects(s, IntegratedVerifierBase.BadRoot.selector);
    }

    // Commitments --------------------------------------------------------------------------------

    function test_rejects_a_repeated_role() public {
        IntegratedRegisterVerifier.Submission memory s = _sub();
        s.att.roleOfField[1] = s.att.roleOfField[0];
        _rejects(s, IntegratedVerifierBase.BadRoles.selector);
    }

    function test_rejects_a_role_out_of_range() public {
        IntegratedRegisterVerifier.Submission memory s = _sub();
        s.att.roleOfField[0] = 5;
        _rejects(s, IntegratedVerifierBase.BadRoles.selector);
    }

    function test_rejects_a_missing_commitment() public {
        IntegratedRegisterVerifier.Submission memory s = _sub();
        uint8[] memory roles = new uint8[](4);
        for (uint256 i = 0; i < 4; i++) {
            roles[i] = s.att.roleOfField[i];
        }
        s.att.roleOfField = roles;
        _rejects(s, IntegratedVerifierBase.BadRoles.selector);
    }

    function test_rejects_swapped_field_positions() public {
        IntegratedRegisterVerifier.Submission memory s = _sub();
        (s.att.roleOfField[0], s.att.roleOfField[1]) = (s.att.roleOfField[1], s.att.roleOfField[0]);
        _rejects(s, IntegratedVerifierBase.BadRoot.selector);
    }

    function test_rejects_hashes_swapped_between_roles() public {
        IntegratedRegisterVerifier.Submission memory s = _sub();
        (s.att.hashes[2], s.att.hashes[3]) = (s.att.hashes[3], s.att.hashes[2]);
        _rejects(s, IntegratedVerifierBase.BadRoot.selector);
    }

    function test_rejects_another_direction_or_range() public {
        IntegratedRegisterVerifier.Submission memory s = _sub();
        s.att.prefixes[2][1] = 0x00; // Sent instead of Received
        vm.expectRevert(abi.encodeWithSelector(IntegratedVerifierBase.BadPrefix.selector, 2));
        baseline.verify(s);
    }

    function test_rejects_another_request_line() public {
        IntegratedRegisterVerifier.Submission memory s = _sub();
        s.att.requestBlinder = bytes16(uint128(s.att.requestBlinder) ^ 1);
        _rejects(s, IntegratedVerifierBase.BadRequestLine.selector);
    }

    function test_rejects_another_property_in_the_request_line() public {
        IntegratedRegisterVerifier.Submission memory s = _sub();
        s.txData.propertyId = bytes32(uint256(s.txData.propertyId) ^ (1 << 200));
        _rejects(s, IntegratedVerifierBase.BadRequestLine.selector);
    }

    function test_rejects_another_response_structure() public {
        IntegratedRegisterVerifier.Submission memory s = _sub();
        s.att.structure[0] = bytes1(uint8(s.att.structure[0]) ^ 1);
        _rejects(s, IntegratedVerifierBase.BadStructure.selector);
    }

    function test_rejects_an_opaque_field_changed() public {
        IntegratedRegisterVerifier.Submission memory s = _sub();
        s.att.certCommitment[5] = bytes1(uint8(s.att.certCommitment[5]) ^ 1);
        _rejects(s, IntegratedVerifierBase.BadRoot.selector);
    }

    // Proof --------------------------------------------------------------------------------------

    function test_rejects_a_statement_changed_after_proving() public {
        IntegratedRegisterVerifier.Submission memory s = _sub();
        s.submitter = address(0xBEEF);
        _rejects(s, IntegratedVerifierBase.BadProof.selector);
    }

    function test_rejects_a_proof_for_another_deployment() public {
        // The same submission checked by a baseline at another address: another EIP-712 domain.
        Groth16Verifier phiR = new Groth16Verifier();
        IntegratedRegisterVerifier other = new IntegratedRegisterVerifier(baseConfig(fx), IPhiRVerifier(address(phiR)));
        vm.expectRevert(IntegratedVerifierBase.BadProof.selector);
        other.verify(_sub());
    }
}

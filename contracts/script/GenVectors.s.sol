// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Script} from "forge-std/Script.sol";
import {PPREVEncoding} from "../src/PPREVEncoding.sol";
import {INotaryVerifier} from "../src/interfaces/INotaryVerifier.sol";
import {PPREVHarness} from "../test/utils/PPREVHarness.sol";
import {NotarySigner, XR, XA, XS} from "../test/utils/NotarySigner.sol";
import {TypedDataJson} from "../test/utils/TypedDataJson.sol";
import {SampleStatements} from "../test/utils/SampleStatements.sol";

/// @notice Writes ../test-vectors/eip712.json: C_tx and the three statement digests for fixed inputs.
/// Every value is computed by the contract's encoding path and checked against the independent test
/// signer and Foundry's EIP-712 encoder before it is written.
/// Usage: forge script script/GenVectors.s.sol
contract GenVectors is Script, NotarySigner, TypedDataJson {
    string internal constant OUT = "../test-vectors/eip712.json";

    function run() external {
        PPREVHarness h = new PPREVHarness(address(1), INotaryVerifier(address(2)), 300, 14 days, 3, 5000);
        uint256 chainId = vm.getChainId();
        address vc = address(h);

        bytes32 cTx = h.exposedCommitment(SampleStatements.txData(), SampleStatements.POLICY_R, SampleStatements.SALT);
        require(cTx == SampleStatements.cTx(), "C_tx mismatch");

        string memory json = string.concat(
            "{",
            field("domain", domainJson(chainId, vc)),
            ",",
            field("types", typesJson()),
            ",",
            field("commitment", commitmentJson(cTx)),
            ",",
            field("register", registerJson(h, chainId, vc)),
            ",",
            field("apply", applyJson(h, chainId, vc)),
            ",",
            field("settle", settleJson(h, chainId, vc)),
            "}"
        );
        vm.writeFile(OUT, json);
    }

    function typesJson() internal pure returns (string memory) {
        return string.concat(
            "{",
            field("TxData", q(TX_DATA_TYPE)),
            ",",
            field("Register", q(string.concat(REGISTER_TYPE, TX_DATA_TYPE))),
            ",",
            field("Apply", q(string.concat(APPLY_TYPE, TX_DATA_TYPE))),
            ",",
            field("Settle", q(string.concat(SETTLE_TYPE, TX_DATA_TYPE))),
            "}"
        );
    }

    function commitmentJson(bytes32 cTx) internal pure returns (string memory) {
        return string.concat(
            "{",
            field("txData", txDataJson(SampleStatements.txData())),
            ",",
            hexField("policyIdR", SampleStatements.POLICY_R),
            ",",
            hexField("r", SampleStatements.SALT),
            ",",
            hexField("cTx", cTx),
            "}"
        );
    }

    function vectorJson(string memory message, bytes32 structHash, bytes32 d) internal pure returns (string memory) {
        return string.concat(
            "{", field("message", message), ",", hexField("structHash", structHash), ",", hexField("digest", d), "}"
        );
    }

    function checked(
        PPREVHarness h,
        bytes32 structHash,
        bytes32 independent,
        string memory typedDataJson,
        uint256 chainId,
        address vc
    ) internal view returns (bytes32 d) {
        require(structHash == independent, "struct hash mismatch");
        d = h.exposedHashTypedData(structHash);
        require(d == digestFor(independent, chainId, vc), "digest mismatch (test signer)");
        require(d == vm.eip712HashTypedData(typedDataJson), "digest mismatch (Foundry)");
    }

    function registerJson(PPREVHarness h, uint256 chainId, address vc) internal view returns (string memory) {
        XR memory x = SampleStatements.register();
        PPREVEncoding.RegisterStatement memory s = PPREVEncoding.RegisterStatement({
            cTx: x.cTx,
            txDataHash: h.exposedHashTxData(x.txData),
            policyId: x.policyId,
            submitter: x.submitter,
            eta: x.eta,
            tAtt: x.tAtt
        });
        bytes32 structHash = h.exposedHashRegister(s);
        bytes32 d = checked(h, structHash, structHashR(x), typedDataR(x, chainId, vc), chainId, vc);
        return vectorJson(messageR(x), structHash, d);
    }

    function applyJson(PPREVHarness h, uint256 chainId, address vc) internal view returns (string memory) {
        XA memory x = SampleStatements.apply_();
        PPREVEncoding.ApplyStatement memory s = PPREVEncoding.ApplyStatement({
            txId: x.txId,
            cTx: x.cTx,
            txDataHash: h.exposedHashTxData(x.txData),
            cB: x.cB,
            policyId: x.policyId,
            submitter: x.submitter,
            eta: x.eta,
            tAtt: x.tAtt
        });
        bytes32 structHash = h.exposedHashApply(s);
        bytes32 d = checked(h, structHash, structHashA(x), typedDataA(x, chainId, vc), chainId, vc);
        return vectorJson(messageA(x), structHash, d);
    }

    function settleJson(PPREVHarness h, uint256 chainId, address vc) internal view returns (string memory) {
        XS memory x = SampleStatements.settle();
        PPREVEncoding.SettleStatement memory s;
        s.engId = x.engId;
        s.txId = x.txId;
        s.cTx = x.cTx;
        s.txDataHash = h.exposedHashTxData(x.txData);
        s.cB = x.cB;
        s.expiresAt = x.expiresAt;
        s.policyId = x.policyId;
        s.submitter = x.submitter;
        s.eta = x.eta;
        s.tAtt = x.tAtt;
        bytes32 structHash = h.exposedHashSettle(s);
        bytes32 d = checked(h, structHash, structHashS(x), typedDataS(x, chainId, vc), chainId, vc);
        return vectorJson(messageS(x), structHash, d);
    }
}

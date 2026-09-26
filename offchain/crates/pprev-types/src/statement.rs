//! Phase statements x_R, x_A, x_S (Table III) as EIP-712 structs, and the transaction commitment
//! C_tx (Eq. (2)). The structs and type strings are those of `contracts/src/PPREVEncoding.sol`; the
//! primary type of each statement is its domain tag tag_psi (D8).

use alloy_primitives::{Address, B256, keccak256};
use alloy_sol_types::{Eip712Domain, SolStruct, SolValue, eip712_domain, sol};

sol! {
    /// Public transaction parameters txData (D5).
    #[derive(Debug, PartialEq, Eq)]
    struct TxData {
        bytes32 propertyId;
        uint256 amount;
        uint256 settlementShare;
    }

    /// x_R; the primary type is tag_R.
    #[derive(Debug, PartialEq, Eq)]
    struct Register {
        bytes32 cTx;
        TxData txData;
        bytes32 policyId;
        address submitter;
        bytes32 eta;
        uint64 tAtt;
    }

    /// x_A; the primary type is tag_A.
    #[derive(Debug, PartialEq, Eq)]
    struct Apply {
        uint256 txId;
        bytes32 cTx;
        TxData txData;
        bytes32 cB;
        bytes32 policyId;
        address submitter;
        bytes32 eta;
        uint64 tAtt;
    }

    /// x_S; the primary type is tag_S.
    #[derive(Debug, PartialEq, Eq)]
    struct Settle {
        uint256 engId;
        uint256 txId;
        bytes32 cTx;
        TxData txData;
        bytes32 cB;
        uint256 expiresAt;
        bytes32 policyId;
        address submitter;
        bytes32 eta;
        uint64 tAtt;
    }
}

/// EIP-712 domain of one PPREV deployment: name "PPREV", version "1", chain ID, contract address.
pub fn domain(chain_id: u64, verifying_contract: Address) -> Eip712Domain {
    eip712_domain! {
        name: "PPREV",
        version: "1",
        chain_id: chain_id,
        verifying_contract: verifying_contract,
    }
}

/// C_tx = keccak256(txData || policyID_R || r), with every part a 32-byte word (Eq. (2)).
pub fn commitment(tx_data: &TxData, policy_id_r: B256, r: B256) -> B256 {
    keccak256((tx_data.clone(), policy_id_r, r).abi_encode())
}

/// enc(tag_psi, x_psi, chainID, addr_SC): the EIP-712 digest that sigma signs.
pub fn digest<S: SolStruct>(statement: &S, domain: &Eip712Domain) -> B256 {
    statement.eip712_signing_hash(domain)
}

#[cfg(test)]
mod tests {
    use alloy_primitives::U256;
    use serde_json::Value;

    use super::*;

    fn vectors() -> Value {
        serde_json::from_str(include_str!("../../../../test-vectors/eip712.json")).unwrap()
    }

    fn b256(v: &Value) -> B256 {
        v.as_str().unwrap().parse().unwrap()
    }

    fn u256(v: &Value) -> U256 {
        v.as_str().unwrap().parse().unwrap()
    }

    fn u64_of(v: &Value) -> u64 {
        v.as_str().unwrap().parse().unwrap()
    }

    fn address(v: &Value) -> Address {
        v.as_str().unwrap().parse().unwrap()
    }

    fn tx_data(v: &Value) -> TxData {
        TxData {
            propertyId: b256(&v["propertyId"]),
            amount: u256(&v["amount"]),
            settlementShare: u256(&v["settlementShare"]),
        }
    }

    fn vector_domain(v: &Value) -> Eip712Domain {
        let d = &v["domain"];
        assert_eq!(d["name"], "PPREV");
        assert_eq!(d["version"], "1");
        domain(u64_of(&d["chainId"]), address(&d["verifyingContract"]))
    }

    #[test]
    fn type_strings_match_the_contract() {
        let v = vectors();
        let types = &v["types"];
        assert_eq!(
            TxData::eip712_encode_type(),
            types["TxData"].as_str().unwrap()
        );
        assert_eq!(
            Register::eip712_encode_type(),
            types["Register"].as_str().unwrap()
        );
        assert_eq!(
            Apply::eip712_encode_type(),
            types["Apply"].as_str().unwrap()
        );
        assert_eq!(
            Settle::eip712_encode_type(),
            types["Settle"].as_str().unwrap()
        );
    }

    #[test]
    fn commitment_matches_the_contract() {
        let v = vectors();
        let c = &v["commitment"];
        assert_eq!(
            commitment(&tx_data(&c["txData"]), b256(&c["policyIdR"]), b256(&c["r"])),
            b256(&c["cTx"])
        );
    }

    #[test]
    fn register_digest_matches_the_contract() {
        let v = vectors();
        let m = &v["register"]["message"];
        let x = Register {
            cTx: b256(&m["cTx"]),
            txData: tx_data(&m["txData"]),
            policyId: b256(&m["policyId"]),
            submitter: address(&m["submitter"]),
            eta: b256(&m["eta"]),
            tAtt: u64_of(&m["tAtt"]),
        };
        assert_eq!(x.eip712_hash_struct(), b256(&v["register"]["structHash"]));
        assert_eq!(
            digest(&x, &vector_domain(&v)),
            b256(&v["register"]["digest"])
        );
    }

    #[test]
    fn apply_digest_matches_the_contract() {
        let v = vectors();
        let m = &v["apply"]["message"];
        let x = Apply {
            txId: u256(&m["txId"]),
            cTx: b256(&m["cTx"]),
            txData: tx_data(&m["txData"]),
            cB: b256(&m["cB"]),
            policyId: b256(&m["policyId"]),
            submitter: address(&m["submitter"]),
            eta: b256(&m["eta"]),
            tAtt: u64_of(&m["tAtt"]),
        };
        assert_eq!(x.eip712_hash_struct(), b256(&v["apply"]["structHash"]));
        assert_eq!(digest(&x, &vector_domain(&v)), b256(&v["apply"]["digest"]));
    }

    #[test]
    fn settle_digest_matches_the_contract() {
        let v = vectors();
        let m = &v["settle"]["message"];
        let x = Settle {
            engId: u256(&m["engId"]),
            txId: u256(&m["txId"]),
            cTx: b256(&m["cTx"]),
            txData: tx_data(&m["txData"]),
            cB: b256(&m["cB"]),
            expiresAt: u256(&m["expiresAt"]),
            policyId: b256(&m["policyId"]),
            submitter: address(&m["submitter"]),
            eta: b256(&m["eta"]),
            tAtt: u64_of(&m["tAtt"]),
        };
        assert_eq!(x.eip712_hash_struct(), b256(&v["settle"]["structHash"]));
        assert_eq!(digest(&x, &vector_domain(&v)), b256(&v["settle"]["digest"]));
    }

    #[test]
    fn digest_depends_on_chain_and_contract() {
        let v = vectors();
        let m = &v["register"]["message"];
        let x = Register {
            cTx: b256(&m["cTx"]),
            txData: tx_data(&m["txData"]),
            policyId: b256(&m["policyId"]),
            submitter: address(&m["submitter"]),
            eta: b256(&m["eta"]),
            tAtt: u64_of(&m["tAtt"]),
        };
        let d = vector_domain(&v);
        let chain = d.chain_id.unwrap().to::<u64>();
        let contract = d.verifying_contract.unwrap();
        assert_ne!(digest(&x, &domain(chain + 1, contract)), digest(&x, &d));
        assert_ne!(
            digest(&x, &domain(chain, Address::repeat_byte(0x42))),
            digest(&x, &d)
        );
    }
}

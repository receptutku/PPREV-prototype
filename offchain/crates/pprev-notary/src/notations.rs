//! The notary's record of used settlement notations (M2): the notation nullifier of Settle. The
//! first Settle statement the policy verifier signs on a notation binds that notation, under its
//! Settle policy, to the engagement of the statement: chain ID and verifying contract of the
//! EIP-712 domain, and engId. A later Settle statement on the same notation is signed only for the
//! same engagement, so that one settlement record cannot settle two engagements while an honest
//! owner can still have sigma_S re-issued (a new nonce and a new attestation) for its engagement.
//!
//! The record is an append-only file with one binding per line, loaded at start, with the
//! persistence and crash semantics of the nonce record (`nonces.rs`):
//!
//! ```text
//! <policyID_S: 64 hex> <notation identifier> <chainId: 64 hex> <verifying contract: 40 hex> <engId: 64 hex>
//! ```
//!
//! A notation identifier is a request target segment (letters, digits, '-', 1 to 64 bytes), so the
//! fields cannot run into each other.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use alloy_primitives::{Address, B256, U256};
use anyhow::{Context, Result, bail, ensure};

use crate::phases::check_subject;

/// The engagement a notation settles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Engagement {
    pub chain_id: U256,
    pub contract: Address,
    pub eng_id: U256,
}

impl std::fmt::Display for Engagement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "engagement {} of {} on chain {}",
            self.eng_id, self.contract, self.chain_id
        )
    }
}

pub struct NotationStore {
    path: PathBuf,
    file: File,
    bound: HashMap<(B256, String), Engagement>,
}

fn word<const N: usize>(field: Option<&str>) -> Option<[u8; N]> {
    let field = field?;
    (field.len() == 2 * N)
        .then(|| hex::decode(field).ok()?.try_into().ok())
        .flatten()
}

impl NotationStore {
    /// Opens the record at `path`, creating it if it does not exist. A malformed line, or a
    /// notation bound twice, is an error: a record that cannot be read in full cannot tell which
    /// engagement a notation settles.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("opening {}", path.display()))?;
        let mut bound = HashMap::new();
        for (i, line) in BufReader::new(&file).lines().enumerate() {
            let line = line.with_context(|| format!("reading {}", path.display()))?;
            let at = || format!("{} line {}", path.display(), i + 1);
            let mut fields = line.split(' ');
            let policy_id = word::<32>(fields.next());
            let notation = fields.next().map(str::to_owned);
            let chain_id = word::<32>(fields.next());
            let contract = word::<20>(fields.next());
            let eng_id = word::<32>(fields.next());
            let (
                Some(policy_id),
                Some(notation),
                Some(chain_id),
                Some(contract),
                Some(eng_id),
                None,
            ) = (
                policy_id,
                notation,
                chain_id,
                contract,
                eng_id,
                fields.next(),
            )
            else {
                bail!("{}: not a notation binding", at());
            };
            check_subject(&notation).with_context(at)?;
            let engagement = Engagement {
                chain_id: U256::from_be_bytes(chain_id),
                contract: Address::from(contract),
                eng_id: U256::from_be_bytes(eng_id),
            };
            ensure!(
                bound
                    .insert((B256::from(policy_id), notation.clone()), engagement)
                    .is_none(),
                "{}: notation {notation} is bound twice",
                at()
            );
        }
        Ok(Self { path, file, bound })
    }

    /// The engagement `notation` is bound to under `policy_id`, if any.
    pub fn get(&self, policy_id: B256, notation: &str) -> Option<&Engagement> {
        self.bound.get(&(policy_id, notation.to_owned()))
    }

    pub fn len(&self) -> usize {
        self.bound.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bound.is_empty()
    }

    /// Refuses unless `notation` is unused under `policy_id` or bound to `engagement`.
    pub fn check(&self, policy_id: B256, notation: &str, engagement: &Engagement) -> Result<()> {
        if let Some(bound) = self.get(policy_id, notation) {
            ensure!(
                bound == engagement,
                "notation {notation} has already settled {bound}, not {engagement}"
            );
        }
        Ok(())
    }

    /// Binds `notation` to `engagement` before the notary signs the first Settle statement on it, so
    /// that no crash can let the notation settle two engagements. Writes nothing if the notation is
    /// already bound to `engagement`; fails if it is bound to another one.
    pub fn record(
        &mut self,
        policy_id: B256,
        notation: &str,
        engagement: Engagement,
    ) -> Result<()> {
        self.check(policy_id, notation, &engagement)?;
        if self.get(policy_id, notation).is_some() {
            return Ok(());
        }
        check_subject(notation)?;
        writeln!(
            self.file,
            "{} {notation} {} {} {}",
            hex::encode(policy_id),
            hex::encode(engagement.chain_id.to_be_bytes::<32>()),
            hex::encode(engagement.contract),
            hex::encode(engagement.eng_id.to_be_bytes::<32>()),
        )
        .and_then(|()| self.file.sync_data())
        .with_context(|| format!("appending to {}", self.path.display()))?;
        self.bound
            .insert((policy_id, notation.to_owned()), engagement);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("pprev-notations-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("notations.log");
        let _ = std::fs::remove_file(&path);
        path
    }

    fn engagement(eng_id: u64) -> Engagement {
        Engagement {
            chain_id: U256::from(31337),
            contract: Address::repeat_byte(0x5a),
            eng_id: U256::from(eng_id),
        }
    }

    fn policy() -> B256 {
        B256::repeat_byte(0x5e)
    }

    #[test]
    fn a_notation_settles_one_engagement() {
        let path = temp_path("once");
        let mut store = NotationStore::open(&path).unwrap();
        store.record(policy(), "N-0001", engagement(1)).unwrap();
        // The same engagement again: accepted, and not written twice.
        store.record(policy(), "N-0001", engagement(1)).unwrap();
        assert!(store.check(policy(), "N-0001", &engagement(1)).is_ok());
        let err = store
            .check(policy(), "N-0001", &engagement(2))
            .unwrap_err()
            .to_string();
        assert!(err.contains("has already settled engagement 1"), "{err}");
        assert!(store.record(policy(), "N-0001", engagement(2)).is_err());
        // Another chain or another contract is another engagement.
        let mut other_chain = engagement(1);
        other_chain.chain_id = U256::from(1);
        assert!(store.check(policy(), "N-0001", &other_chain).is_err());
        let mut other_contract = engagement(1);
        other_contract.contract = Address::repeat_byte(0x5b);
        assert!(store.check(policy(), "N-0001", &other_contract).is_err());
        // Other notations, and the same notation under another Settle policy, are unused.
        store.record(policy(), "N-0002", engagement(2)).unwrap();
        store
            .record(B256::repeat_byte(0x5f), "N-0001", engagement(2))
            .unwrap();
        assert_eq!(store.len(), 3);
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 3);
    }

    #[test]
    fn the_record_survives_a_restart() {
        let path = temp_path("restart");
        {
            let mut store = NotationStore::open(&path).unwrap();
            store.record(policy(), "N-0001", engagement(1)).unwrap();
        }
        let mut store = NotationStore::open(&path).unwrap();
        assert_eq!(store.get(policy(), "N-0001"), Some(&engagement(1)));
        assert!(store.record(policy(), "N-0001", engagement(2)).is_err());
        store.record(policy(), "N-0001", engagement(1)).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let expected = format!(
            "{} N-0001 {:064x} {} {:064x}\n",
            "5e".repeat(32),
            31337,
            "5a".repeat(20),
            1
        );
        assert_eq!(text, expected);
    }

    #[test]
    fn a_malformed_record_is_rejected() {
        let path = temp_path("malformed");
        let good = format!(
            "{} N-0001 {} {} {}",
            "5e".repeat(32),
            "00".repeat(32),
            "5a".repeat(20),
            "00".repeat(32)
        );
        for bad in [
            "not-a-binding".to_owned(),
            format!("{good} extra"),
            good.replace("N-0001", "N 0001"),
            good.replace("N-0001", "../x"),
            good.replacen(&"5a".repeat(20), &"5a".repeat(21), 1),
            good[..good.len() - 2].to_owned(),
            format!(
                "{good}\n{}",
                good.replacen(&"00".repeat(32), &"01".repeat(32), 1)
            ),
        ] {
            std::fs::write(&path, format!("{bad}\n")).unwrap();
            assert!(NotationStore::open(&path).is_err(), "{bad}");
        }
        std::fs::write(&path, format!("{good}\n")).unwrap();
        assert_eq!(NotationStore::open(&path).unwrap().len(), 1);
    }
}

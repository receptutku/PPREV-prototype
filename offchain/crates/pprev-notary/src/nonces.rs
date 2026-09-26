//! The notary's record of signed nonces (D20). The notary refuses to sign a statement whose nonce
//! it has already signed (Section V-B, step (d)), in any phase. The record is an append-only file
//! with one nonce per line as 64 hex digits, loaded at start.

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

pub struct NonceStore {
    path: PathBuf,
    file: File,
    seen: HashSet<[u8; 32]>,
}

impl NonceStore {
    /// Opens the record at `path`, creating it if it does not exist. A malformed line is an error:
    /// a record that cannot be read in full cannot tell which nonces were signed.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("opening {}", path.display()))?;
        let mut seen = HashSet::new();
        for (i, line) in BufReader::new(&file).lines().enumerate() {
            let line = line.with_context(|| format!("reading {}", path.display()))?;
            let bytes = hex::decode(line.trim())
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .with_context(|| {
                    format!("{} line {}: not a 32-byte nonce", path.display(), i + 1)
                })?;
            seen.insert(bytes);
        }
        Ok(Self { path, file, seen })
    }

    pub fn contains(&self, eta: &[u8; 32]) -> bool {
        self.seen.contains(eta)
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// Records `eta` before the notary signs with it, so that no crash can let the same nonce be
    /// signed twice. Fails if `eta` is already recorded.
    pub fn record(&mut self, eta: [u8; 32]) -> Result<()> {
        if self.seen.contains(&eta) {
            bail!("nonce 0x{} has already been signed", hex::encode(eta));
        }
        writeln!(self.file, "{}", hex::encode(eta))
            .and_then(|()| self.file.sync_data())
            .with_context(|| format!("appending to {}", self.path.display()))?;
        self.seen.insert(eta);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("pprev-nonces-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nonces.log");
        let _ = std::fs::remove_file(&path);
        path
    }

    #[test]
    fn a_nonce_is_recorded_once() {
        let path = temp_path("once");
        let mut store = NonceStore::open(&path).unwrap();
        store.record([1; 32]).unwrap();
        store.record([2; 32]).unwrap();
        let err = store.record([1; 32]).unwrap_err().to_string();
        assert!(err.contains("already been signed"), "{err}");
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn the_record_survives_a_restart() {
        let path = temp_path("restart");
        {
            let mut store = NonceStore::open(&path).unwrap();
            store.record([7; 32]).unwrap();
        }
        let mut store = NonceStore::open(&path).unwrap();
        assert!(store.contains(&[7; 32]));
        assert!(store.record([7; 32]).is_err());
        store.record([8; 32]).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text, format!("{}\n{}\n", "07".repeat(32), "08".repeat(32)));
    }

    #[test]
    fn a_malformed_record_is_rejected() {
        let path = temp_path("malformed");
        std::fs::write(&path, format!("{}\nnot-a-nonce\n", "01".repeat(32))).unwrap();
        assert!(NonceStore::open(&path).is_err());
        std::fs::write(&path, "0102\n").unwrap();
        assert!(NonceStore::open(&path).is_err());
    }
}

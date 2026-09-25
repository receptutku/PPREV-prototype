//! Fixed-layout title response (D4).
//!
//! The layout file holds the parameters: widths, server name, path, status line. This module owns
//! the template and computes every byte range from it, so the registry, the prover, and the policy
//! verifier agree on offsets without any offset being written by hand.

use std::ops::Range;
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};

/// Keys of the JSON body, in the order they appear.
pub const KEY_ACCOUNT: &str = "account";
pub const KEY_RECORD: &str = "record";
pub const KEY_PROPERTY_ID: &str = "propertyId";
pub const KEY_OWNERS: &str = "owners";
pub const KEY_ENCUMBRANCE: &str = "encumbrance";
pub const KEY_ASSESSED_VALUE: &str = "assessedValue";
pub const KEY_RECORD_DATE: &str = "recordDate";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Layout {
    pub id: String,
    pub server_name: String,
    pub path_prefix: String,
    pub status_line: String,
    pub content_type: String,
    /// Single ASCII character that pads every value to its width.
    pub padding: String,
    pub account_width: usize,
    pub property_id_width: usize,
    pub owner_slots: usize,
    pub encumbrance_width: usize,
    pub assessed_value_width: usize,
    pub record_date_width: usize,
}

/// A title record as the registry stores it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TitleRecord {
    pub property_id: String,
    pub owners: Vec<String>,
    pub encumbrance: String,
    pub assessed_value: String,
    pub record_date: String,
}

/// Byte ranges of one rendered response, as offsets into the received transcript.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResponseRanges {
    /// Total response length (head and body).
    pub len: usize,
    pub status_line: Range<usize>,
    pub content_type_line: Range<usize>,
    /// Every JSON key as it appears on the wire: quote, name, quote, colon.
    pub keys: Vec<Range<usize>>,
    /// Value of `account`: the identifier of the logged-in account.
    pub account: Range<usize>,
    /// From the first byte of the first owner slot to the last byte of the last slot.
    pub owners: Range<usize>,
    /// Start of each owner slot, relative to `owners.start`.
    pub owner_slot_offsets: Vec<usize>,
    pub property_id: Range<usize>,
}

impl ResponseRanges {
    /// Ranges the presentation reveals (D26): status line, Content-Type line, JSON keys.
    pub fn revealed(&self) -> Vec<Range<usize>> {
        let mut out = vec![self.status_line.clone(), self.content_type_line.clone()];
        out.extend(self.keys.iter().cloned());
        out
    }

    /// Ranges committed with a hash and never opened (D3), in the order account, owners, propertyId.
    pub fn hidden(&self) -> [Range<usize>; 3] {
        [
            self.account.clone(),
            self.owners.clone(),
            self.property_id.clone(),
        ]
    }
}

#[derive(Clone, Debug)]
pub struct Rendered {
    pub bytes: Vec<u8>,
    pub ranges: ResponseRanges,
}

impl Layout {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Self::from_json(&text)
    }

    pub fn from_json(text: &str) -> Result<Self> {
        let layout: Layout = serde_json::from_str(text).context("parsing layout")?;
        layout.validate()?;
        Ok(layout)
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.padding.len() == 1 && self.padding.is_ascii(),
            "padding must be one ASCII character"
        );
        ensure!(self.owner_slots > 0, "owner_slots must be positive");
        for (name, w) in [
            ("accountWidth", self.account_width),
            ("propertyIdWidth", self.property_id_width),
            ("encumbranceWidth", self.encumbrance_width),
            ("assessedValueWidth", self.assessed_value_width),
            ("recordDateWidth", self.record_date_width),
        ] {
            ensure!(w > 0, "{name} must be positive");
        }
        Ok(())
    }

    pub fn padding_byte(&self) -> u8 {
        self.padding.as_bytes()[0]
    }

    /// Request target for a property: `{pathPrefix}{propertyId}`.
    pub fn path(&self, property_id: &str) -> String {
        format!("{}{}", self.path_prefix, property_id)
    }

    /// First line of the notarised request, without CRLF.
    pub fn request_line(&self, property_id: &str) -> String {
        format!("GET {} HTTP/1.1", self.path(property_id))
    }

    /// Pads `value` to `width` with the padding character; rejects values that are too long or that
    /// could break the JSON template.
    pub fn pad(&self, value: &str, width: usize) -> Result<String> {
        ensure!(value.is_ascii(), "value {value:?} is not ASCII");
        ensure!(
            !value.contains(['"', '\\']),
            "value {value:?} contains a quote or backslash"
        );
        if value.len() > width {
            bail!("value {value:?} is longer than its width {width}");
        }
        let mut out = value.to_string();
        out.extend(std::iter::repeat_n(
            self.padding.chars().next().unwrap_or(' '),
            width - value.len(),
        ));
        Ok(out)
    }

    /// Renders the full HTTP response for `account` viewing `record`, with the byte range of every
    /// part.
    pub fn render_response(&self, account: &str, record: &TitleRecord) -> Result<Rendered> {
        ensure!(
            record.owners.len() <= self.owner_slots,
            "record has {} owners, the layout allows {}",
            record.owners.len(),
            self.owner_slots
        );

        let mut body = Writer::default();
        let mut keys = Vec::new();
        body.lit("{");
        keys.push(body.key(KEY_ACCOUNT));
        let account = body.string(&self.pad(account, self.account_width)?);
        body.lit(",");
        keys.push(body.key(KEY_RECORD));
        body.lit("{");
        keys.push(body.key(KEY_PROPERTY_ID));
        let property_id = body.string(&self.pad(&record.property_id, self.property_id_width)?);
        body.lit(",");
        keys.push(body.key(KEY_OWNERS));
        body.lit("[");
        let mut slots = Vec::with_capacity(self.owner_slots);
        for i in 0..self.owner_slots {
            if i > 0 {
                body.lit(",");
            }
            let owner = record.owners.get(i).map(String::as_str).unwrap_or("");
            slots.push(body.string(&self.pad(owner, self.account_width)?));
        }
        body.lit("],");
        keys.push(body.key(KEY_ENCUMBRANCE));
        body.string(&self.pad(&record.encumbrance, self.encumbrance_width)?);
        body.lit(",");
        keys.push(body.key(KEY_ASSESSED_VALUE));
        body.string(&self.pad(&record.assessed_value, self.assessed_value_width)?);
        body.lit(",");
        keys.push(body.key(KEY_RECORD_DATE));
        body.string(&self.pad(&record.record_date, self.record_date_width)?);
        body.lit("}}");

        let mut head = Writer::default();
        let status_line = head.lit(&self.status_line);
        head.lit("\r\n");
        let content_type_line = head.lit(&format!("Content-Type: {}", self.content_type));
        head.lit("\r\n");
        head.lit(&format!("Content-Length: {}\r\n", body.bytes.len()));
        head.lit("Connection: close\r\n\r\n");

        let shift = head.bytes.len();
        let at = |r: Range<usize>| r.start + shift..r.end + shift;
        let owners = at(slots[0].start..slots[slots.len() - 1].end);
        let ranges = ResponseRanges {
            len: head.bytes.len() + body.bytes.len(),
            status_line,
            content_type_line,
            keys: keys.into_iter().map(at).collect(),
            account: at(account),
            owner_slot_offsets: slots
                .iter()
                .map(|s| s.start + shift - owners.start)
                .collect(),
            owners,
            property_id: at(property_id),
        };
        let mut bytes = head.bytes;
        bytes.extend_from_slice(&body.bytes);
        Ok(Rendered { bytes, ranges })
    }

    /// The response for an empty record. Every byte outside the field values is the same for every
    /// record, so this is the reference for the revealed ranges.
    pub fn template(&self) -> Result<Rendered> {
        let blank = TitleRecord {
            property_id: String::new(),
            owners: Vec::new(),
            encumbrance: String::new(),
            assessed_value: String::new(),
            record_date: String::new(),
        };
        self.render_response("", &blank)
    }

    /// Byte ranges of the response for any record.
    pub fn ranges(&self) -> Result<ResponseRanges> {
        Ok(self.template()?.ranges)
    }

    /// `txData.propertyId`: the property identifier as ASCII, left-aligned and zero-padded to 32 bytes.
    pub fn property_id_word(&self, property_id: &str) -> Result<[u8; 32]> {
        ensure!(property_id.is_ascii(), "property id is not ASCII");
        ensure!(
            property_id.len() <= self.property_id_width && property_id.len() <= 32,
            "property id {property_id:?} exceeds its width"
        );
        let mut word = [0u8; 32];
        word[..property_id.len()].copy_from_slice(property_id.as_bytes());
        Ok(word)
    }
}

/// Appends template pieces and reports where each landed.
#[derive(Default)]
struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    fn lit(&mut self, s: &str) -> Range<usize> {
        let start = self.bytes.len();
        self.bytes.extend_from_slice(s.as_bytes());
        start..self.bytes.len()
    }

    /// Writes `"name":` and returns its range.
    fn key(&mut self, name: &str) -> Range<usize> {
        self.lit(&format!("\"{name}\":"))
    }

    /// Writes a quoted value and returns the range of the value without quotes.
    fn string(&mut self, value: &str) -> Range<usize> {
        self.lit("\"");
        let range = self.lit(value);
        self.lit("\"");
        range
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layout() -> Layout {
        Layout::from_json(include_str!("../../../../policies/layouts/title-v1.json")).unwrap()
    }

    fn record(owners: &[&str]) -> TitleRecord {
        TitleRecord {
            property_id: "TR-06-CANKAYA-000123".into(),
            owners: owners.iter().map(|s| s.to_string()).collect(),
            encumbrance: "N".into(),
            assessed_value: "000000012500000".into(),
            record_date: "2026-09-24".into(),
        }
    }

    #[test]
    fn renders_fields_at_their_ranges() {
        let l = layout();
        let r = l
            .render_response(
                "ACC-000000000001",
                &record(&["ACC-000000000001", "ACC-000000000002"]),
            )
            .unwrap();
        let s = |range: &Range<usize>| {
            std::str::from_utf8(&r.bytes[range.clone()])
                .unwrap()
                .to_string()
        };
        assert_eq!(r.bytes.len(), r.ranges.len);
        assert_eq!(s(&r.ranges.status_line), "HTTP/1.1 200 OK");
        assert_eq!(
            s(&r.ranges.content_type_line),
            "Content-Type: application/json"
        );
        assert_eq!(s(&r.ranges.account), "ACC-000000000001");
        assert_eq!(s(&r.ranges.property_id), "TR-06-CANKAYA-000123");
        let owners = s(&r.ranges.owners);
        let slot = |i: usize| {
            owners[r.ranges.owner_slot_offsets[i]..r.ranges.owner_slot_offsets[i] + l.account_width]
                .to_string()
        };
        assert_eq!(slot(0), "ACC-000000000001");
        assert_eq!(slot(1), "ACC-000000000002");
        assert_eq!(slot(2), " ".repeat(16));
        let keys: Vec<String> = r.ranges.keys.iter().map(s).collect();
        assert_eq!(
            keys,
            [
                "\"account\":",
                "\"record\":",
                "\"propertyId\":",
                "\"owners\":",
                "\"encumbrance\":",
                "\"assessedValue\":",
                "\"recordDate\":"
            ]
        );
        // The body is valid JSON with the expected values.
        let head_end = r.bytes.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let json: serde_json::Value = serde_json::from_slice(&r.bytes[head_end..]).unwrap();
        assert_eq!(json["record"]["owners"][1], "ACC-000000000002");
    }

    #[test]
    fn every_record_has_the_same_ranges() {
        let l = layout();
        let expected = l.ranges().unwrap();
        for owners in [
            &[][..],
            &["ACC-000000000001"][..],
            &[
                "ACC-000000000001",
                "ACC-000000000002",
                "ACC-000000000003",
                "ACC-000000000004",
            ][..],
        ] {
            let r = l
                .render_response("ACC-000000000009", &record(owners))
                .unwrap();
            assert_eq!(r.ranges, expected);
        }
    }

    #[test]
    fn rejects_values_that_do_not_fit() {
        let l = layout();
        let mut rec = record(&[]);
        rec.property_id = "X".repeat(21);
        assert!(l.render_response("ACC-000000000001", &rec).is_err());
        assert!(
            l.render_response("ACC-\"00000000001", &record(&[]))
                .is_err()
        );
        assert!(
            l.render_response("ACC-000000000001", &record(&["1", "2", "3", "4", "5"]))
                .is_err()
        );
    }

    #[test]
    fn property_id_word_is_left_aligned() {
        let w = layout().property_id_word("TR-06-CANKAYA-000123").unwrap();
        assert_eq!(&w[..20], b"TR-06-CANKAYA-000123");
        assert!(w[20..].iter().all(|b| *b == 0));
    }
}

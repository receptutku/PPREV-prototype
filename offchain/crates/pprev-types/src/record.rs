//! Fixed-layout single-record responses of the Apply and Settle sources (D4): the eligibility
//! record of phi_A (`income-v1`) and the tenancy notation of phi_S (`tenancy-v1`).
//!
//! The body is `{"account":"<id>","record":{"<key>":"<value>",...}}` with every value padded to its
//! width, so, as for the title layout, every byte range is fixed by the layout file and computed
//! here, never written by hand. The account and every field value are hidden behind hash
//! commitments; the status line, the Content-Type line, and the JSON keys are revealed.

use std::ops::Range;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use crate::layout::{KEY_ACCOUNT, KEY_RECORD, ResponseShape, Writer, pad_value};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordField {
    pub key: String,
    pub width: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordLayout {
    pub id: String,
    pub server_name: String,
    /// Request target prefix; the target is the prefix followed by the record's subject.
    pub path_prefix: String,
    pub status_line: String,
    pub content_type: String,
    /// Single ASCII character that pads every value to its width.
    pub padding: String,
    pub account_width: usize,
    /// The record's fields, in the order they appear.
    pub fields: Vec<RecordField>,
}

/// Byte ranges of one rendered response, as offsets into the received transcript.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordRanges {
    /// Total response length (head and body).
    pub len: usize,
    pub status_line: Range<usize>,
    pub content_type_line: Range<usize>,
    /// Every JSON key as it appears on the wire: quote, name, quote, colon.
    pub keys: Vec<Range<usize>>,
    /// Value of `account`: the identifier of the logged-in account.
    pub account: Range<usize>,
    /// Value of each field, in layout order.
    pub fields: Vec<Range<usize>>,
}

impl RecordRanges {
    /// Ranges the presentation reveals (D26): status line, Content-Type line, JSON keys.
    pub fn revealed(&self) -> Vec<Range<usize>> {
        let mut out = vec![self.status_line.clone(), self.content_type_line.clone()];
        out.extend(self.keys.iter().cloned());
        out
    }

    /// Ranges committed with a hash and never opened (D3): the account, then every field.
    pub fn hidden(&self) -> Vec<Range<usize>> {
        let mut out = vec![self.account.clone()];
        out.extend(self.fields.iter().cloned());
        out
    }
}

#[derive(Clone, Debug)]
pub struct RenderedRecord {
    pub bytes: Vec<u8>,
    pub ranges: RecordRanges,
}

impl RecordLayout {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Self::from_json(&text)
    }

    pub fn from_json(text: &str) -> Result<Self> {
        let layout: RecordLayout = serde_json::from_str(text).context("parsing record layout")?;
        layout.validate()?;
        Ok(layout)
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.padding.len() == 1 && self.padding.is_ascii(),
            "padding must be one ASCII character"
        );
        ensure!(self.account_width > 0, "accountWidth must be positive");
        ensure!(!self.fields.is_empty(), "a record has at least one field");
        for (i, field) in self.fields.iter().enumerate() {
            ensure!(field.width > 0, "field {:?} has width 0", field.key);
            ensure!(
                !field.key.is_empty()
                    && field
                        .key
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_'),
                "field key {:?} is not a plain identifier",
                field.key
            );
            ensure!(
                field.key != KEY_ACCOUNT && field.key != KEY_RECORD,
                "field key {:?} is reserved",
                field.key
            );
            ensure!(
                self.fields[..i].iter().all(|f| f.key != field.key),
                "field {:?} appears twice",
                field.key
            );
        }
        Ok(())
    }

    pub fn padding_byte(&self) -> u8 {
        self.padding.as_bytes()[0]
    }

    /// Request target for a subject: `{pathPrefix}{subject}`.
    pub fn path(&self, subject: &str) -> String {
        format!("{}{}", self.path_prefix, subject)
    }

    /// First line of the notarised request, without CRLF.
    pub fn request_line(&self, subject: &str) -> String {
        format!("GET {} HTTP/1.1", self.path(subject))
    }

    /// Pads `value` to `width` with the padding character.
    pub fn pad(&self, value: &str, width: usize) -> Result<String> {
        pad_value(&self.padding, value, width)
    }

    /// Position of the field `key`.
    pub fn index_of(&self, key: &str) -> Result<usize> {
        self.fields
            .iter()
            .position(|f| f.key == key)
            .with_context(|| format!("layout {} has no field {key:?}", self.id))
    }

    pub fn width_of(&self, key: &str) -> Result<usize> {
        Ok(self.fields[self.index_of(key)?].width)
    }

    /// Renders the full HTTP response for `account` viewing a record with `values`, one per field
    /// in layout order, with the byte range of every part.
    pub fn render_response(&self, account: &str, values: &[&str]) -> Result<RenderedRecord> {
        ensure!(
            values.len() == self.fields.len(),
            "{} values for the {} fields of layout {}",
            values.len(),
            self.fields.len(),
            self.id
        );
        let mut body = Writer::default();
        let mut keys = Vec::new();
        body.lit("{");
        keys.push(body.key(KEY_ACCOUNT));
        let account = body.string(&self.pad(account, self.account_width)?);
        body.lit(",");
        keys.push(body.key(KEY_RECORD));
        body.lit("{");
        let mut fields = Vec::with_capacity(self.fields.len());
        for (i, (field, value)) in self.fields.iter().zip(values).enumerate() {
            if i > 0 {
                body.lit(",");
            }
            keys.push(body.key(&field.key));
            fields.push(body.string(&self.pad(value, field.width)?));
        }
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
        let ranges = RecordRanges {
            len: head.bytes.len() + body.bytes.len(),
            status_line,
            content_type_line,
            keys: keys.into_iter().map(at).collect(),
            account: at(account),
            fields: fields.into_iter().map(at).collect(),
        };
        let mut bytes = head.bytes;
        bytes.extend_from_slice(&body.bytes);
        Ok(RenderedRecord { bytes, ranges })
    }

    /// The response for an empty record: the reference for the revealed ranges.
    pub fn template(&self) -> Result<RenderedRecord> {
        self.render_response("", &vec![""; self.fields.len()])
    }

    /// Byte ranges of the response for any record.
    pub fn ranges(&self) -> Result<RecordRanges> {
        Ok(self.template()?.ranges)
    }

    /// The notarised exchange for `subject`; the hidden ranges are the account, then every field.
    pub fn shape(&self, subject: &str) -> Result<ResponseShape> {
        let template = self.template()?;
        Ok(ResponseShape {
            server_name: self.server_name.clone(),
            path: self.path(subject),
            request_line: self.request_line(subject),
            len: template.ranges.len,
            revealed: template.ranges.revealed(),
            hidden: template.ranges.hidden(),
            template: template.bytes,
        })
    }

    /// A field value as the response carries it (padded to its width), followed by zero bytes up
    /// to 32 bytes: the form of `txData.propertyId` (see `Layout::property_id_word`).
    pub fn word(&self, key: &str, value: &str) -> Result<[u8; 32]> {
        let width = self.width_of(key)?;
        ensure!(width <= 32, "field {key:?} is wider than 32 bytes");
        let value = self.pad(value, width)?;
        let mut word = [0u8; 32];
        word[..value.len()].copy_from_slice(value.as_bytes());
        Ok(word)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn income() -> RecordLayout {
        RecordLayout::from_json(include_str!("../../../../policies/layouts/income-v1.json"))
            .unwrap()
    }

    fn tenancy() -> RecordLayout {
        RecordLayout::from_json(include_str!("../../../../policies/layouts/tenancy-v1.json"))
            .unwrap()
    }

    fn text(bytes: &[u8], range: &Range<usize>) -> String {
        std::str::from_utf8(&bytes[range.clone()])
            .unwrap()
            .to_string()
    }

    #[test]
    fn renders_fields_at_their_ranges() {
        let l = tenancy();
        let r = l
            .render_response(
                "ACC-000000000001",
                &["TR-06-CANKAYA-000123", "ACC-000000000003", "2026-10-21"],
            )
            .unwrap();
        assert_eq!(r.bytes.len(), r.ranges.len);
        assert_eq!(text(&r.bytes, &r.ranges.status_line), "HTTP/1.1 200 OK");
        assert_eq!(text(&r.bytes, &r.ranges.account), "ACC-000000000001");
        let values: Vec<String> = r.ranges.fields.iter().map(|f| text(&r.bytes, f)).collect();
        assert_eq!(
            values,
            ["TR-06-CANKAYA-000123", "ACC-000000000003", "2026-10-21"]
        );
        let keys: Vec<String> = r.ranges.keys.iter().map(|k| text(&r.bytes, k)).collect();
        assert_eq!(
            keys,
            [
                "\"account\":",
                "\"record\":",
                "\"propertyId\":",
                "\"tenant\":",
                "\"recordDate\":"
            ]
        );
        let head_end = r.bytes.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let json: serde_json::Value = serde_json::from_slice(&r.bytes[head_end..]).unwrap();
        assert_eq!(json["record"]["tenant"], "ACC-000000000003");
    }

    #[test]
    fn every_record_has_the_same_ranges() {
        let l = income();
        let expected = l.ranges().unwrap();
        for (account, value) in [
            ("ACC-000000000003", "00000000000000000001"),
            ("A", "3"),
            ("", ""),
        ] {
            assert_eq!(
                l.render_response(account, &[value]).unwrap().ranges,
                expected
            );
        }
    }

    #[test]
    fn hidden_ranges_are_the_account_and_the_fields() {
        let r = tenancy().ranges().unwrap();
        assert_eq!(r.hidden().len(), 4);
        assert_eq!(r.hidden()[0], r.account);
        assert_eq!(&r.hidden()[1..], &r.fields[..]);
        let shape = tenancy().shape("N-0001").unwrap();
        assert_eq!(shape.request_line, "GET /tenancy/N-0001 HTTP/1.1");
        assert_eq!(shape.hidden, r.hidden());
        assert_eq!(shape.revealed, r.revealed());
        assert_eq!(shape.len, r.len);
    }

    #[test]
    fn rejects_values_that_do_not_fit() {
        let l = income();
        assert!(l.render_response("A", &["1".repeat(21).as_str()]).is_err());
        assert!(l.render_response("A\"", &["1"]).is_err());
        assert!(l.render_response("A", &[]).is_err());
        assert!(l.render_response("A", &["1", "2"]).is_err());
    }

    #[test]
    fn rejects_malformed_layouts() {
        let base = serde_json::json!({
            "id": "x", "serverName": "s", "pathPrefix": "/x", "statusLine": "HTTP/1.1 200 OK",
            "contentType": "application/json", "padding": " ", "accountWidth": 16,
            "fields": [{"key": "a", "width": 1}]
        });
        assert!(RecordLayout::from_json(&base.to_string()).is_ok());
        let with = |fields: serde_json::Value| {
            let mut v = base.clone();
            v["fields"] = fields;
            RecordLayout::from_json(&v.to_string())
        };
        assert!(with(serde_json::json!([])).is_err());
        assert!(with(serde_json::json!([{"key": "a", "width": 0}])).is_err());
        assert!(with(serde_json::json!([{"key": "a\"", "width": 1}])).is_err());
        assert!(with(serde_json::json!([{"key": "account", "width": 1}])).is_err());
        assert!(
            with(serde_json::json!([{"key": "a", "width": 1}, {"key": "a", "width": 2}])).is_err()
        );
    }

    #[test]
    fn property_word_matches_the_title_layout() {
        let title =
            crate::Layout::from_json(include_str!("../../../../policies/layouts/title-v1.json"))
                .unwrap();
        for id in ["TR-06-CANKAYA-000123", "TR-06-X"] {
            assert_eq!(
                tenancy().word("propertyId", id).unwrap(),
                title.property_id_word(id).unwrap()
            );
        }
        assert!(tenancy().word("propertyId", &"X".repeat(21)).is_err());
        assert!(tenancy().word("nope", "X").is_err());
    }
}

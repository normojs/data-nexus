//! Security obligations executed by the PEP after PDP Allow (S3).
//!
//! PDP produces obligations; PEP applies SQL rewrite / result masking without
//! re-asking the policy engine.

use crate::{Column, GatewayResponse, GatewayValue};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// How a column value is masked on the result path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MaskAlgorithm {
    /// Replace with SQL NULL.
    #[default]
    Nullify,
    /// Keep first/last few characters; middle becomes `*`.
    Partial,
    /// Hex prefix of a non-crypto fingerprint (demo-grade, not for passwords).
    Hash,
    /// Fixed replacement string.
    Replace,
    /// Keep a fixed prefix length, mask the rest.
    KeepPrefix,
}

impl MaskAlgorithm {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "" => None,
            "nullify" | "null" => Some(Self::Nullify),
            "partial" | "mask" => Some(Self::Partial),
            "hash" => Some(Self::Hash),
            "replace" => Some(Self::Replace),
            "keep_prefix" | "prefix" => Some(Self::KeepPrefix),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Nullify => "nullify",
            Self::Partial => "partial",
            Self::Hash => "hash",
            Self::Replace => "replace",
            Self::KeepPrefix => "keep_prefix",
        }
    }
}

/// One column mask obligation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaskSpec {
    /// Bare column name (case-insensitive match against result metadata).
    pub column: String,
    pub algorithm: MaskAlgorithm,
    /// Used by [`MaskAlgorithm::Replace`]; default `***`.
    #[serde(default)]
    pub replace_with: String,
    /// Prefix length for partial / keep_prefix (default 3).
    #[serde(default = "default_prefix_len")]
    pub prefix_len: usize,
    /// Suffix length for partial (default 2).
    #[serde(default = "default_suffix_len")]
    pub suffix_len: usize,
    pub rule: String,
}

fn default_prefix_len() -> usize {
    3
}

fn default_suffix_len() -> usize {
    2
}

impl MaskSpec {
    pub fn new(column: impl Into<String>, algorithm: MaskAlgorithm, rule: impl Into<String>) -> Self {
        Self {
            column: column.into(),
            algorithm,
            replace_with: "***".into(),
            prefix_len: default_prefix_len(),
            suffix_len: default_suffix_len(),
            rule: rule.into(),
        }
    }
}


/// Visible result watermark for leak tracing (F14).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum WatermarkMode {
    /// Append a synthetic result column holding the token.
    #[default]
    Column,
    /// Append ` |wm=<token>` to the first string-like cell in each row.
    Suffix,
}

impl WatermarkMode {
    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "suffix" => Self::Suffix,
            _ => Self::Column,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Column => "column",
            Self::Suffix => "suffix",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatermarkSpec {
    pub mode: WatermarkMode,
    /// Column name when mode=column (default `_dn_wm`).
    pub column: String,
    /// Trace token embedded in the result.
    pub token: String,
}

impl WatermarkSpec {
    pub fn column_token(column: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            mode: WatermarkMode::Column,
            column: column.into(),
            token: token.into(),
        }
    }
}

/// Obligations attached to an Allow decision.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Obligations {
    /// Result-path column masks (applied after backend execute).
    pub column_masks: Vec<MaskSpec>,
    /// SQL predicate to AND into SELECT (S3 MVP: static text, no bind params).
    pub row_filter: Option<String>,
    /// Optional max rows returned (result truncation).
    pub max_rows: Option<u64>,
    /// Audit level override (L0/L1/L2); empty keeps policy default.
    pub audit_level: Option<String>,
    /// Optional visible watermark (F14).
    pub watermark: Option<WatermarkSpec>,
}

impl Obligations {
    pub fn is_empty(&self) -> bool {
        self.column_masks.is_empty()
            && self.row_filter.is_none()
            && self.max_rows.is_none()
            && self.audit_level.is_none()
            && self.watermark.is_none()
    }

    pub fn merge(&mut self, other: Obligations) {
        for m in other.column_masks {
            if !self
                .column_masks
                .iter()
                .any(|x| x.column.eq_ignore_ascii_case(&m.column))
            {
                self.column_masks.push(m);
            }
        }
        if self.row_filter.is_none() {
            self.row_filter = other.row_filter;
        } else if let Some(extra) = other.row_filter {
            // Combine with AND when multiple filters match.
            let existing = self.row_filter.take().unwrap_or_default();
            self.row_filter = Some(format!("({existing}) AND ({extra})"));
        }
        match (self.max_rows, other.max_rows) {
            (Some(a), Some(b)) => self.max_rows = Some(a.min(b)),
            (None, Some(b)) => self.max_rows = Some(b),
            _ => {}
        }
        if self.audit_level.is_none() {
            self.audit_level = other.audit_level;
        }
        if self.watermark.is_none() {
            self.watermark = other.watermark;
        }
    }

    pub fn has_result_obligations(&self) -> bool {
        !self.column_masks.is_empty() || self.max_rows.is_some() || self.watermark.is_some()
    }
}

/// Apply mask algorithms to a single cell.
pub fn mask_gateway_value(value: &GatewayValue, spec: &MaskSpec) -> GatewayValue {
    match spec.algorithm {
        MaskAlgorithm::Nullify => GatewayValue::Null,
        MaskAlgorithm::Replace => {
            let rep = if spec.replace_with.is_empty() {
                "***"
            } else {
                spec.replace_with.as_str()
            };
            GatewayValue::String(rep.to_owned())
        }
        MaskAlgorithm::Hash => {
            let s = value_as_display(value);
            GatewayValue::String(format!("hash:{}", simple_fingerprint(&s)))
        }
        MaskAlgorithm::Partial => {
            let s = value_as_display(value);
            GatewayValue::String(partial_mask(&s, spec.prefix_len, spec.suffix_len))
        }
        MaskAlgorithm::KeepPrefix => {
            let s = value_as_display(value);
            GatewayValue::String(keep_prefix_mask(&s, spec.prefix_len))
        }
    }
}

fn value_as_display(value: &GatewayValue) -> String {
    match value {
        GatewayValue::Null => String::new(),
        GatewayValue::Boolean(b) => b.to_string(),
        GatewayValue::Integer(i) => i.to_string(),
        GatewayValue::UnsignedInteger(u) => u.to_string(),
        GatewayValue::Float(f) => f.to_string(),
        GatewayValue::Decimal(s) | GatewayValue::String(s) => s.clone(),
        GatewayValue::Bytes(b) => String::from_utf8_lossy(b).into_owned(),
    }
}

/// Demo fingerprint (FNV-1a 64 → hex). Not cryptographic.
fn simple_fingerprint(input: &str) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

fn partial_mask(s: &str, prefix: usize, suffix: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    let n = chars.len();
    if n == 0 {
        return String::new();
    }
    if prefix + suffix >= n {
        return "*".repeat(n.max(1));
    }
    let mut out = String::new();
    out.extend(chars.iter().take(prefix));
    out.extend(std::iter::repeat('*').take(n - prefix - suffix));
    out.extend(chars.iter().skip(n - suffix));
    out
}

fn keep_prefix_mask(s: &str, prefix: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.is_empty() {
        return String::new();
    }
    let keep = prefix.min(chars.len());
    let mut out: String = chars.iter().take(keep).collect();
    if keep < chars.len() {
        out.push_str("***");
    }
    out
}

/// Inject a static row-filter predicate into a simple SELECT.
///
/// Returns `None` when the SQL is not a rewriteable top-level SELECT.
pub fn inject_row_filter(sql: &str, predicate: &str) -> Option<String> {
    let pred = predicate.trim();
    if pred.is_empty() {
        return Some(sql.to_owned());
    }
    let trimmed = sql.trim_start();
    let upper = trimmed.to_ascii_uppercase();
    if !(upper.starts_with("SELECT") || upper.starts_with("WITH")) {
        return None;
    }
    // Refuse multi-set queries for MVP rewrite safety.
    if upper.contains(" UNION ") {
        return None;
    }
    let _ = find_top_level_keyword(trimmed, "FROM")?;
    let prefix_ws = sql.len() - trimmed.len();

    if let Some(where_idx) = find_top_level_keyword(trimmed, "WHERE") {
        let after_where_kw = where_idx + 5;
        let where_body_start = after_where_kw
            + trimmed[after_where_kw..]
                .chars()
                .take_while(|c| c.is_whitespace())
                .count();
        let rest = &trimmed[where_body_start..];
        let boundary = find_post_where_boundary(rest).unwrap_or(rest.len());
        let body = rest[..boundary].trim_end();
        let tail = rest[boundary..].trim_start();
        let mut out = String::new();
        out.push_str(&sql[..prefix_ws]);
        out.push_str(&trimmed[..where_body_start]);
        out.push('(');
        out.push_str(body);
        out.push_str(") AND (");
        out.push_str(pred);
        out.push(')');
        if !tail.is_empty() {
            out.push(' ');
            out.push_str(tail);
        }
        return Some(out);
    }

    // No WHERE: insert before GROUP/HAVING/ORDER/LIMIT/... or at end.
    let insert_at = find_post_from_boundary(trimmed).unwrap_or(trimmed.len());
    let mut out = String::new();
    out.push_str(&sql[..prefix_ws]);
    out.push_str(trimmed[..insert_at].trim_end());
    out.push_str(" WHERE (");
    out.push_str(pred);
    out.push(')');
    let tail = trimmed[insert_at..].trim_start();
    if !tail.is_empty() {
        out.push(' ');
        out.push_str(tail);
    }
    Some(out)
}

fn find_post_where_boundary(sql: &str) -> Option<usize> {
    const KEYS: &[&str] = &[
        "GROUP", "HAVING", "ORDER", "LIMIT", "FOR", "WINDOW", "FETCH", "OFFSET",
    ];
    let mut best: Option<usize> = None;
    for key in KEYS {
        if let Some(idx) = find_top_level_keyword(sql, key) {
            best = Some(best.map_or(idx, |b| b.min(idx)));
        }
    }
    best
}

fn find_post_from_boundary(sql: &str) -> Option<usize> {
    const KEYS: &[&str] = &[
        "WHERE", "GROUP", "HAVING", "ORDER", "LIMIT", "FOR", "WINDOW", "FETCH", "OFFSET",
    ];
    let mut best: Option<usize> = None;
    for key in KEYS {
        if let Some(idx) = find_top_level_keyword(sql, key) {
            best = Some(best.map_or(idx, |b| b.min(idx)));
        }
    }
    best
}

fn find_top_level_keyword(sql: &str, keyword: &str) -> Option<usize> {
    let upper = sql.to_ascii_uppercase();
    let key = keyword.to_ascii_uppercase();
    let bytes = upper.as_bytes();
    let key_bytes = key.as_bytes();
    let mut depth = 0i32;
    let mut in_single = false;
    let mut in_double = false;
    let mut in_back = false;
    let mut i = 0usize;
    while i + key_bytes.len() <= bytes.len() {
        let c = bytes[i];
        if in_single {
            if c == b'\'' {
                in_single = false;
            }
            i += 1;
            continue;
        }
        if in_double {
            if c == b'"' {
                in_double = false;
            }
            i += 1;
            continue;
        }
        if in_back {
            if c == b'`' {
                in_back = false;
            }
            i += 1;
            continue;
        }
        match c {
            b'\'' => in_single = true,
            b'"' => in_double = true,
            b'`' => in_back = true,
            b'(' => depth += 1,
            b')' => depth -= 1,
            _ => {
                if depth == 0 && bytes[i..].starts_with(key_bytes) {
                    let before_ok = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
                    let after = i + key_bytes.len();
                    let after_ok = after >= bytes.len() || !bytes[after].is_ascii_alphanumeric();
                    if before_ok && after_ok {
                        return Some(i);
                    }
                }
            }
        }
        i += 1;
    }
    None
}

/// Apply result-path obligations to a gateway response (materialized MVP).
pub fn apply_obligations_to_response(
    response: GatewayResponse,
    obligations: &Obligations,
) -> GatewayResponse {
    if !obligations.has_result_obligations() {
        return response;
    }
    match response {
        GatewayResponse::ResultSet { mut columns, mut rows } => {
            let mask_idx = build_mask_index(&columns, &obligations.column_masks);
            if !mask_idx.is_empty() {
                for row in &mut rows {
                    for (col_i, spec) in &mask_idx {
                        if let Some(cell) = row.get_mut(*col_i) {
                            *cell = mask_gateway_value(cell, spec);
                        }
                    }
                }
            }
            if let Some(max) = obligations.max_rows {
                let max = max as usize;
                if rows.len() > max {
                    rows.truncate(max);
                }
            }
            if let Some(wm) = &obligations.watermark {
                apply_watermark_to_resultset(&mut columns, &mut rows, wm);
            }
            GatewayResponse::ResultSet { columns, rows }
        }
        other => other,
    }
}

fn apply_watermark_to_resultset(
    columns: &mut Vec<Column>,
    rows: &mut Vec<Vec<GatewayValue>>,
    wm: &WatermarkSpec,
) {
    match wm.mode {
        WatermarkMode::Column => {
            let name = if wm.column.trim().is_empty() {
                "_dn_wm".to_owned()
            } else {
                wm.column.clone()
            };
            // Avoid duplicate column if re-applied.
            if !columns.iter().any(|c| c.name.eq_ignore_ascii_case(&name)) {
                columns.push(Column {
                    name,
                    data_type: "varchar".into(),
                });
                for row in rows.iter_mut() {
                    row.push(GatewayValue::String(wm.token.clone()));
                }
            }
        }
        WatermarkMode::Suffix => {
            let marker = format!(" |wm={}", wm.token);
            for row in rows.iter_mut() {
                let mut applied = false;
                for cell in row.iter_mut() {
                    match cell {
                        GatewayValue::String(s) => {
                            if !s.contains(" |wm=") {
                                s.push_str(&marker);
                            }
                            applied = true;
                            break;
                        }
                        GatewayValue::Decimal(s) => {
                            // leave decimals alone
                            let _ = s;
                        }
                        _ => {}
                    }
                }
                if !applied {
                    // No string cell: append a synthetic string cell if columns allow growth.
                    // Prefer mutating last cell display via new string value only when empty row.
                    if let Some(last) = row.last_mut() {
                        let base = value_as_display(last);
                        *last = GatewayValue::String(format!("{base}{marker}"));
                    }
                }
            }
        }
    }
}


fn build_mask_index<'a>(
    columns: &[Column],
    masks: &'a [MaskSpec],
) -> Vec<(usize, &'a MaskSpec)> {
    let mut by_name: BTreeMap<String, &MaskSpec> = BTreeMap::new();
    for m in masks {
        by_name.insert(m.column.to_ascii_lowercase(), m);
    }
    let mut out = Vec::new();
    for (i, col) in columns.iter().enumerate() {
        let bare = col
            .name
            .rsplit('.')
            .next()
            .unwrap_or(col.name.as_str())
            .trim_matches('`')
            .trim_matches('"')
            .to_ascii_lowercase();
        if let Some(spec) = by_name.get(&bare) {
            out.push((i, *spec));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_masks_phone() {
        let spec = MaskSpec::new("phone", MaskAlgorithm::Partial, "r");
        let v = mask_gateway_value(&GatewayValue::String("13812345678".into()), &spec);
        assert_eq!(v, GatewayValue::String("138******78".into()));
    }

    #[test]
    fn nullify_and_replace() {
        let n = MaskSpec::new("x", MaskAlgorithm::Nullify, "r");
        assert_eq!(
            mask_gateway_value(&GatewayValue::Integer(9), &n),
            GatewayValue::Null
        );
        let mut r = MaskSpec::new("x", MaskAlgorithm::Replace, "r");
        r.replace_with = "[redacted]".into();
        assert_eq!(
            mask_gateway_value(&GatewayValue::String("a".into()), &r),
            GatewayValue::String("[redacted]".into())
        );
    }

    #[test]
    fn inject_where_on_plain_select() {
        let out = inject_row_filter("SELECT id, name FROM employees", "tenant_id = 1").unwrap();
        let u = out.to_ascii_uppercase();
        assert!(u.contains("WHERE"));
        assert!(u.contains("TENANT_ID = 1"));
        assert!(u.contains("FROM EMPLOYEES"));
    }

    #[test]
    fn inject_and_existing_where() {
        let out =
            inject_row_filter("SELECT id FROM employees WHERE active = 1", "tenant_id = 1").unwrap();
        let u = out.to_ascii_uppercase();
        assert!(u.contains("ACTIVE = 1"));
        assert!(u.contains("TENANT_ID = 1"));
        assert!(u.contains(" AND "));
    }

    #[test]
    fn apply_masks_to_resultset() {
        let mut obl = Obligations::default();
        obl.column_masks
            .push(MaskSpec::new("salary", MaskAlgorithm::Nullify, "m"));
        let resp = GatewayResponse::ResultSet {
            columns: vec![
                Column {
                    name: "id".into(),
                    data_type: "int".into(),
                },
                Column {
                    name: "salary".into(),
                    data_type: "int".into(),
                },
            ],
            rows: vec![vec![GatewayValue::Integer(1), GatewayValue::Integer(90000)]],
        };
        let out = apply_obligations_to_response(resp, &obl);
        match out {
            GatewayResponse::ResultSet { rows, .. } => {
                assert_eq!(rows[0][0], GatewayValue::Integer(1));
                assert_eq!(rows[0][1], GatewayValue::Null);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn watermark_column_appended() {
        let mut obl = Obligations::default();
        obl.watermark = Some(WatermarkSpec::column_token("_dn_wm", "abc123"));
        let resp = GatewayResponse::ResultSet {
            columns: vec![Column {
                name: "id".into(),
                data_type: "int".into(),
            }],
            rows: vec![vec![GatewayValue::Integer(1)]],
        };
        let out = apply_obligations_to_response(resp, &obl);
        match out {
            GatewayResponse::ResultSet { columns, rows } => {
                assert_eq!(columns.len(), 2);
                assert_eq!(columns[1].name, "_dn_wm");
                assert_eq!(rows[0][1], GatewayValue::String("abc123".into()));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn watermark_suffix_appended() {
        let mut obl = Obligations::default();
        obl.watermark = Some(WatermarkSpec {
            mode: WatermarkMode::Suffix,
            column: String::new(),
            token: "t9".into(),
        });
        let resp = GatewayResponse::ResultSet {
            columns: vec![Column {
                name: "name".into(),
                data_type: "varchar".into(),
            }],
            rows: vec![vec![GatewayValue::String("alice".into())]],
        };
        let out = apply_obligations_to_response(resp, &obl);
        match out {
            GatewayResponse::ResultSet { rows, .. } => match &rows[0][0] {
                GatewayValue::String(s) => assert!(s.contains("|wm=t9"), "{s}"),
                other => panic!("{other:?}"),
            },
            other => panic!("{other:?}"),
        }
    }
}

//! Time-window policy helpers (F27).
//!
//! Rules restrict actions to (or outside) a daily window on selected weekdays.
//! Used for "writes only during business hours" without a full BPM.

use chrono::{Datelike, FixedOffset, Local, TimeZone, Timelike, Utc, Weekday};
use serde::{Deserialize, Serialize};

use crate::{GatewayError, GatewayResult};

/// Time-of-day policy rule (F27).
///
/// Example — deny writes outside Mon–Fri 09:00–18:00 UTC:
///
/// ```toml
/// [[security.time_rules]]
/// name = "work-hours-writes"
/// effect = "deny"
/// outside = true
/// days = ["mon", "tue", "wed", "thu", "fri"]
/// start = "09:00"
/// end = "18:00"
/// timezone = "UTC"
/// actions = ["insert", "update", "delete", "ddl"]
/// message = "writes only allowed Mon–Fri 09:00–18:00 UTC"
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityTimeRuleConfig {
    pub name: String,
    /// `deny` (default) or `require_ticket`.
    #[serde(default = "default_time_effect")]
    pub effect: String,
    /// When true (default), the rule fires when **outside** the window.
    /// When false, fires when **inside** the window (e.g. maintenance freeze).
    #[serde(default = "default_true")]
    pub outside: bool,
    /// Weekdays: mon..sun (empty = every day).
    #[serde(default)]
    pub days: Vec<String>,
    /// Local time of day `HH:MM` (inclusive start).
    #[serde(default = "default_start")]
    pub start: String,
    /// Local time of day `HH:MM` (exclusive end). `start == end` ⇒ empty window.
    #[serde(default = "default_end")]
    pub end: String,
    /// `UTC` (default), `local`, or fixed offset `+08:00` / `-05:30`.
    #[serde(default = "default_tz")]
    pub timezone: String,
    /// Statement actions this rule applies to (empty = insert/update/delete/ddl).
    #[serde(default)]
    pub actions: Vec<String>,
    /// Optional subject globs; empty = all.
    #[serde(default)]
    pub subjects: Vec<String>,
    /// Optional table globs; empty = any table.
    #[serde(default)]
    pub tables: Vec<String>,
    /// Ticket type when effect = require_ticket.
    #[serde(default = "default_ticket_type")]
    pub ticket_type: String,
    #[serde(default)]
    pub message: String,
}

fn default_time_effect() -> String {
    "deny".into()
}
fn default_true() -> bool {
    true
}
fn default_start() -> String {
    "09:00".into()
}
fn default_end() -> String {
    "18:00".into()
}
fn default_tz() -> String {
    "UTC".into()
}
fn default_ticket_type() -> String {
    "high_risk".into()
}

impl Default for SecurityTimeRuleConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            effect: default_time_effect(),
            outside: true,
            days: Vec::new(),
            start: default_start(),
            end: default_end(),
            timezone: default_tz(),
            actions: Vec::new(),
            subjects: Vec::new(),
            tables: Vec::new(),
            ticket_type: default_ticket_type(),
            message: String::new(),
        }
    }
}

impl SecurityTimeRuleConfig {
    pub fn validate(&self, idx: usize) -> GatewayResult<()> {
        if self.name.trim().is_empty() {
            return Err(GatewayError::Configuration(format!(
                "security.time_rules[{idx}].name must not be empty"
            )));
        }
        match self.effect.to_ascii_lowercase().as_str() {
            "deny" | "require_ticket" => {}
            other => {
                return Err(GatewayError::Configuration(format!(
                    "security.time_rules[{idx}].effect must be deny or require_ticket, got '{other}'"
                )));
            }
        }
        if self.effect.eq_ignore_ascii_case("require_ticket")
            && self.ticket_type.trim().is_empty()
        {
            return Err(GatewayError::Configuration(format!(
                "security.time_rules[{idx}].ticket_type must not be empty when effect=require_ticket"
            )));
        }
        parse_hhmm(&self.start).map_err(|e| {
            GatewayError::Configuration(format!(
                "security.time_rules[{idx}].start invalid: {e}"
            ))
        })?;
        parse_hhmm(&self.end).map_err(|e| {
            GatewayError::Configuration(format!("security.time_rules[{idx}].end invalid: {e}"))
        })?;
        for d in &self.days {
            if parse_weekday(d).is_none() {
                return Err(GatewayError::Configuration(format!(
                    "security.time_rules[{idx}].days entry '{d}' must be mon..sun"
                )));
            }
        }
        parse_timezone_offset_minutes(&self.timezone).map_err(|e| {
            GatewayError::Configuration(format!(
                "security.time_rules[{idx}].timezone invalid: {e}"
            ))
        })?;
        Ok(())
    }

    /// Whether this rule should fire for the given wall-clock instant (unix seconds).
    pub fn matches_now(&self, now_unix_secs: i64) -> bool {
        let Ok(offset_mins) = parse_timezone_offset_minutes(&self.timezone) else {
            return false;
        };
        let Ok(start_m) = parse_hhmm(&self.start) else {
            return false;
        };
        let Ok(end_m) = parse_hhmm(&self.end) else {
            return false;
        };

        let (weekday, minute_of_day) = civil_parts(now_unix_secs, offset_mins);

        if !self.days.is_empty() {
            let day_ok = self.days.iter().any(|d| {
                parse_weekday(d)
                    .map(|w| w == weekday)
                    .unwrap_or(false)
            });
            if !day_ok {
                // Outside listed days: treat as "outside window" for outside=true.
                return self.outside;
            }
        }

        let inside = is_inside_window(minute_of_day, start_m, end_m);
        if self.outside {
            !inside
        } else {
            inside
        }
    }
}

/// Parse `HH:MM` or `H:MM` into minutes since midnight.
pub fn parse_hhmm(s: &str) -> Result<u32, String> {
    let s = s.trim();
    let parts: Vec<_> = s.split(':').collect();
    if parts.len() != 2 {
        return Err(format!("expected HH:MM, got '{s}'"));
    }
    let h: u32 = parts[0]
        .parse()
        .map_err(|_| format!("bad hour in '{s}'"))?;
    let m: u32 = parts[1]
        .parse()
        .map_err(|_| format!("bad minute in '{s}'"))?;
    if h > 23 || m > 59 {
        return Err(format!("out of range HH:MM '{s}'"));
    }
    Ok(h * 60 + m)
}

fn parse_weekday(s: &str) -> Option<Weekday> {
    match s.trim().to_ascii_lowercase().as_str() {
        "mon" | "monday" => Some(Weekday::Mon),
        "tue" | "tues" | "tuesday" => Some(Weekday::Tue),
        "wed" | "wednesday" => Some(Weekday::Wed),
        "thu" | "thur" | "thurs" | "thursday" => Some(Weekday::Thu),
        "fri" | "friday" => Some(Weekday::Fri),
        "sat" | "saturday" => Some(Weekday::Sat),
        "sun" | "sunday" => Some(Weekday::Sun),
        _ => None,
    }
}

/// Returns offset minutes east of UTC. `local` uses the process local offset at evaluation time.
pub fn parse_timezone_offset_minutes(tz: &str) -> Result<i32, String> {
    let t = tz.trim();
    if t.is_empty() || t.eq_ignore_ascii_case("utc") || t.eq_ignore_ascii_case("z") {
        return Ok(0);
    }
    if t.eq_ignore_ascii_case("local") {
        return Ok(Local::now().offset().local_minus_utc() / 60);
    }
    // +HH:MM / -HH:MM / +HHMM
    let (sign, rest) = if let Some(r) = t.strip_prefix('+') {
        (1i32, r)
    } else if let Some(r) = t.strip_prefix('-') {
        (-1i32, r)
    } else {
        return Err(format!("expected UTC, local, or ±HH:MM, got '{tz}'"));
    };
    let rest = rest.trim();
    let (h, m) = if rest.contains(':') {
        let p: Vec<_> = rest.split(':').collect();
        if p.len() != 2 {
            return Err(format!("bad offset '{tz}'"));
        }
        (
            p[0].parse::<i32>().map_err(|_| format!("bad offset hour '{tz}'"))?,
            p[1].parse::<i32>().map_err(|_| format!("bad offset min '{tz}'"))?,
        )
    } else if rest.len() == 4 && rest.chars().all(|c| c.is_ascii_digit()) {
        (
            rest[0..2].parse().unwrap_or(0),
            rest[2..4].parse().unwrap_or(0),
        )
    } else if rest.len() == 2 && rest.chars().all(|c| c.is_ascii_digit()) {
        (rest.parse().unwrap_or(0), 0)
    } else {
        return Err(format!("bad offset '{tz}'"));
    };
    if !(0..=14).contains(&h) || !(0..=59).contains(&m) {
        return Err(format!("offset out of range '{tz}'"));
    }
    Ok(sign * (h * 60 + m))
}

/// Half-open window. `start == end` ⇒ never inside. Overnight when start > end.
pub fn is_inside_window(minute_of_day: u32, start: u32, end: u32) -> bool {
    if start == end {
        return false;
    }
    if start < end {
        minute_of_day >= start && minute_of_day < end
    } else {
        // e.g. 22:00–06:00
        minute_of_day >= start || minute_of_day < end
    }
}

fn civil_parts(now_unix_secs: i64, offset_minutes: i32) -> (Weekday, u32) {
    let offset = FixedOffset::east_opt(offset_minutes * 60).unwrap_or(FixedOffset::east_opt(0).unwrap());
    let dt = offset.timestamp_opt(now_unix_secs, 0).single().unwrap_or_else(|| {
        Utc.timestamp_opt(now_unix_secs, 0)
            .single()
            .unwrap_or_else(|| Utc::now())
            .with_timezone(&offset)
    });
    let weekday = dt.weekday();
    let minute_of_day = dt.hour() * 60 + dt.minute();
    (weekday, minute_of_day)
}

/// Current unix seconds (overridable in tests via env `DATA_NEXUS_SECURITY_NOW_UNIX`).
pub fn security_now_unix_secs() -> i64 {
    if let Ok(v) = std::env::var("DATA_NEXUS_SECURITY_NOW_UNIX") {
        if let Ok(n) = v.trim().parse::<i64>() {
            return n;
        }
    }
    Utc::now().timestamp()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_times_and_window() {
        assert_eq!(parse_hhmm("09:00").unwrap(), 9 * 60);
        assert_eq!(parse_hhmm("18:30").unwrap(), 18 * 60 + 30);
        assert!(is_inside_window(10 * 60, 9 * 60, 18 * 60));
        assert!(!is_inside_window(8 * 60, 9 * 60, 18 * 60));
        assert!(!is_inside_window(9 * 60, 9 * 60, 9 * 60)); // empty
        // overnight
        assert!(is_inside_window(23 * 60, 22 * 60, 6 * 60));
        assert!(is_inside_window(3 * 60, 22 * 60, 6 * 60));
        assert!(!is_inside_window(12 * 60, 22 * 60, 6 * 60));
    }

    #[test]
    fn work_hours_outside_utc() {
        // 2026-07-17 is Friday.
        let fri_10 = chrono::DateTime::parse_from_rfc3339("2026-07-17T10:00:00Z")
            .unwrap()
            .timestamp();
        let fri_20 = chrono::DateTime::parse_from_rfc3339("2026-07-17T20:00:00Z")
            .unwrap()
            .timestamp();
        let sat_10 = chrono::DateTime::parse_from_rfc3339("2026-07-18T10:00:00Z")
            .unwrap()
            .timestamp();

        let rule = SecurityTimeRuleConfig {
            name: "work".into(),
            outside: true,
            days: vec!["mon".into(), "tue".into(), "wed".into(), "thu".into(), "fri".into()],
            start: "09:00".into(),
            end: "18:00".into(),
            timezone: "UTC".into(),
            ..Default::default()
        };
        assert!(!rule.matches_now(fri_10), "Fri 10:00 should be inside → outside=false");
        assert!(rule.matches_now(fri_20), "Fri 20:00 outside hours");
        assert!(rule.matches_now(sat_10), "Sat outside days");
    }

    #[test]
    fn empty_window_always_outside() {
        let rule = SecurityTimeRuleConfig {
            name: "never".into(),
            outside: true,
            days: vec![],
            start: "00:00".into(),
            end: "00:00".into(),
            timezone: "UTC".into(),
            ..Default::default()
        };
        let now = chrono::DateTime::parse_from_rfc3339("2026-07-17T12:00:00Z")
            .unwrap()
            .timestamp();
        assert!(rule.matches_now(now));
    }

    #[test]
    fn timezone_offset() {
        assert_eq!(parse_timezone_offset_minutes("UTC").unwrap(), 0);
        assert_eq!(parse_timezone_offset_minutes("+08:00").unwrap(), 8 * 60);
        assert_eq!(parse_timezone_offset_minutes("-05:30").unwrap(), -5 * 60 - 30);
    }
}

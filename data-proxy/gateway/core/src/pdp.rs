//! Local PDP for data-plane access control (S1 table/statement + S2 columns).
//!
//! Evaluates `SecurityPolicyConfig.rules` against subject + statement action +
//! tables, and optionally column ACL against an [`ObjectSet`] provided by the
//! runtime extractor.

use crate::object_set::{ColumnAclOutcome, ObjectSet, StarPolicy};
use crate::obligations::{inject_row_filter, MaskAlgorithm, MaskSpec, Obligations, WatermarkMode, WatermarkSpec};
use crate::ticket::{
    extract_ticket_id, global_ticket_store, is_write_without_where, strip_ticket_comment,
};
use crate::{
    CommandSummary, DialectParser, GatewayCommand, SecurityColumnTagConfig,
    SecurityHighRiskRuleConfig, SecurityMaskRuleConfig, SecurityPolicyConfig, SecurityRuleConfig,
    SecurityTimeRuleConfig, SecurityWatermarkConfig,
};

/// Data-plane identity (not Admin JWT).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject {
    pub subject_id: String,
    pub db_user: Option<String>,
    pub database: Option<String>,
}

impl Subject {
    /// Bind from protocol session user (source: `protocol_user`).
    pub fn from_protocol_user(user: Option<&str>, database: Option<&str>) -> Self {
        let db_user = user.map(|u| u.to_owned());
        let subject_id = db_user
            .clone()
            .filter(|u| !u.is_empty())
            .unwrap_or_else(|| "anonymous".into());
        Self {
            subject_id,
            db_user,
            database: database.map(|d| d.to_owned()),
        }
    }
}

/// Coarse statement class for rule matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatementAction {
    Select,
    Insert,
    Update,
    Delete,
    Ddl,
    Tcl,
    Other,
}

impl StatementAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Select => "select",
            Self::Insert => "insert",
            Self::Update => "update",
            Self::Delete => "delete",
            Self::Ddl => "ddl",
            Self::Tcl => "tcl",
            Self::Other => "other",
        }
    }

    pub fn from_keyword(keyword: &str) -> Self {
        let k = keyword.trim().to_ascii_uppercase();
        match k.as_str() {
            "SELECT" | "WITH" | "VALUES" | "TABLE" | "SHOW" | "EXPLAIN" | "DESCRIBE" | "DESC" => {
                Self::Select
            }
            "INSERT" | "REPLACE" => Self::Insert,
            "UPDATE" => Self::Update,
            "DELETE" => Self::Delete,
            "CREATE" | "ALTER" | "DROP" | "TRUNCATE" | "RENAME" | "COMMENT" => Self::Ddl,
            "BEGIN" | "START" | "COMMIT" | "ROLLBACK" | "SAVEPOINT" | "RELEASE" => Self::Tcl,
            _ => Self::Other,
        }
    }
}

/// Input to a single PDP evaluation.
#[derive(Debug, Clone)]
pub struct AccessRequest<'a> {
    pub subject: &'a Subject,
    pub service: &'a str,
    pub action: StatementAction,
    pub tables: Vec<String>,
    /// Bare column names already known (from ObjectSet); empty for table-only.
    pub columns: Vec<String>,
    pub sql: Option<&'a str>,
}

/// Local policy decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityDecision {
    /// Allow without rewrite; may still carry result-path obligations (mask).
    Allow { obligations: Obligations },
    /// Allow with SQL rewrite (column strip and/or row filter) + optional result obligations.
    AllowRewrite {
        sql: String,
        obligations: Obligations,
    },
    /// High-risk SQL requires a ticket; message tells client how to attach one.
    RequireTicket {
        rule: String,
        ticket_type: String,
        message: String,
    },
    Deny { rule: String, message: String },
}

impl SecurityDecision {
    pub fn is_deny(&self) -> bool {
        matches!(self, Self::Deny { .. } | Self::RequireTicket { .. })
    }

    pub fn obligations(&self) -> Obligations {
        match self {
            Self::Allow { obligations } | Self::AllowRewrite { obligations, .. } => {
                obligations.clone()
            }
            Self::Deny { .. } | Self::RequireTicket { .. } => Obligations::default(),
        }
    }

    pub fn allow_empty() -> Self {
        Self::Allow {
            obligations: Obligations::default(),
        }
    }
}

/// Compiled local PDP snapshot (cheap to clone via Arc at runtime).
#[derive(Debug, Clone)]
pub struct LocalPdp {
    fail_closed: bool,
    star_policy: StarPolicy,
    rules: Vec<SecurityRuleConfig>,
    mask_rules: Vec<SecurityMaskRuleConfig>,
    column_tags: Vec<SecurityColumnTagConfig>,
    high_risk_rules: Vec<SecurityHighRiskRuleConfig>,
    time_rules: Vec<SecurityTimeRuleConfig>,
    default_max_rows: Option<u64>,
    watermark: SecurityWatermarkConfig,
    /// Optional Cedar table/action engine (F26, feature `security-cedar`).
    #[cfg(feature = "security-cedar")]
    cedar: Option<crate::CedarEngine>,
    /// True when config asked for cedar backend (even if load failed).
    #[cfg(feature = "security-cedar")]
    cedar_required: bool,
}

impl LocalPdp {
    /// Build PDP when security is enabled; `None` when disabled (fast path).
    pub fn from_config(config: &SecurityPolicyConfig) -> Option<Self> {
        if !config.enabled {
            return None;
        }
        #[cfg(feature = "security-cedar")]
        let (cedar, cedar_required) = if config.pdp.backend.eq_ignore_ascii_case("cedar") {
            match crate::cedar_pdp::try_load_from_config(&config.pdp.policy_dir) {
                Ok(eng) => (eng, true),
                Err(e) => {
                    tracing::error!(
                        target: "data_nexus::security",
                        error = %e,
                        "failed to load Cedar PDP; authorize will deny (fail closed)"
                    );
                    (None, true)
                }
            }
        } else {
            (None, false)
        };

        Some(Self {
            fail_closed: config.fail_closed,
            star_policy: StarPolicy::from_config(&config.star_policy),
            rules: config.rules.clone(),
            mask_rules: config.mask_rules.clone(),
            column_tags: config.column_tags.clone(),
            high_risk_rules: config.high_risk_rules.clone(),
            time_rules: config.time_rules.clone(),
            default_max_rows: config.streaming.max_rows,
            watermark: config.watermark.clone(),
            #[cfg(feature = "security-cedar")]
            cedar,
            #[cfg(feature = "security-cedar")]
            cedar_required,
        })
    }

    pub fn fail_closed(&self) -> bool {
        self.fail_closed
    }

    pub fn star_policy(&self) -> StarPolicy {
        self.star_policy
    }

    pub fn rules(&self) -> &[SecurityRuleConfig] {
        &self.rules
    }

    pub fn has_column_rules(&self) -> bool {
        self.rules.iter().any(|r| !r.columns.is_empty())
    }

    pub fn has_mask_config(&self) -> bool {
        !self.column_tags.is_empty() && !self.mask_rules.is_empty()
    }

    pub fn evaluate(&self, request: &AccessRequest<'_>) -> SecurityDecision {
        for rule in &self.rules {
            // Column-only rules are handled in `evaluate_column_acl`.
            if !rule.columns.is_empty() {
                continue;
            }
            if !rule_matches(rule, request) {
                continue;
            }
            match rule.effect.to_ascii_lowercase().as_str() {
                "deny" => {
                    return SecurityDecision::Deny {
                        rule: rule.name.clone(),
                        message: format!(
                            "security policy '{}' denied {} on service '{}'",
                            rule.name,
                            request.action.as_str(),
                            request.service
                        ),
                    };
                }
                "allow" => {
                    return SecurityDecision::Allow {
                        obligations: Obligations::default(),
                    };
                }
                _ => continue,
            }
        }
        SecurityDecision::Allow {
            obligations: Obligations::default(),
        }
    }

    /// Table/statement authorize using heuristic table extraction (S1 path).
    pub fn authorize_command(
        &self,
        subject: &Subject,
        service: &str,
        command: &GatewayCommand,
        dialect: &dyn DialectParser,
    ) -> SecurityDecision {
        self.authorize_command_with_objects(subject, service, command, dialect, None)
    }

    /// Authorize with optional AST-derived [`ObjectSet`] (S2/S3).
    pub fn authorize_command_with_objects(
        &self,
        subject: &Subject,
        service: &str,
        command: &GatewayCommand,
        dialect: &dyn DialectParser,
        objects: Option<&ObjectSet>,
    ) -> SecurityDecision {
        match command {
            GatewayCommand::Ping | GatewayCommand::Quit | GatewayCommand::CloseStatement { .. } => {
                SecurityDecision::allow_empty()
            }
            GatewayCommand::Begin | GatewayCommand::Commit | GatewayCommand::Rollback => {
                let request = AccessRequest {
                    subject,
                    service,
                    action: StatementAction::Tcl,
                    tables: Vec::new(),
                    columns: Vec::new(),
                    sql: None,
                };
                self.evaluate(&request)
            }
            GatewayCommand::UseDatabase { database } => {
                let request = AccessRequest {
                    subject,
                    service,
                    action: StatementAction::Other,
                    tables: vec![database.clone()],
                    columns: Vec::new(),
                    sql: None,
                };
                self.evaluate(&request)
            }
            GatewayCommand::Execute { .. } => {
                if self.fail_closed {
                    SecurityDecision::Deny {
                        rule: "fail_closed".into(),
                        message:
                            "security policy deny: prepared EXECUTE not classified (fail_closed)"
                                .into(),
                    }
                } else {
                    SecurityDecision::allow_empty()
                }
            }
            GatewayCommand::Query { sql } | GatewayCommand::Prepare { sql } => {
                if let Some(set) = objects {
                    if set.parse_failed && set.objects.is_empty() && self.fail_closed {
                        return SecurityDecision::Deny {
                            rule: "fail_closed".into(),
                            message:
                                "security policy deny: SQL object extraction failed (fail_closed)"
                                    .into(),
                        };
                    }
                }

                let keyword = dialect.leading_keyword(sql);
                let action = match keyword.as_deref() {
                    Some(k) => StatementAction::from_keyword(k),
                    None => {
                        if self.fail_closed {
                            return SecurityDecision::Deny {
                                rule: "fail_closed".into(),
                                message:
                                    "security policy deny: empty or unparseable SQL (fail_closed)"
                                        .into(),
                            };
                        }
                        StatementAction::Other
                    }
                };

                let (tables, columns) = if let Some(set) = objects {
                    if set.parse_failed && !set.objects.is_empty() {
                        (set.tables(), collect_bare_columns(set))
                    } else if set.parse_failed {
                        (extract_table_names(sql), Vec::new())
                    } else {
                        (set.tables(), collect_bare_columns(set))
                    }
                } else {
                    (extract_table_names(sql), Vec::new())
                };

                let request = AccessRequest {
                    subject,
                    service,
                    action,
                    tables: tables.clone(),
                    columns: columns.clone(),
                    sql: Some(sql.as_str()),
                };

                let table_decision = self.evaluate(&request);
                if table_decision.is_deny() {
                    return table_decision;
                }

                // F26: optional Cedar table/action gate (feature security-cedar).
                if let Some(deny) = self.evaluate_cedar(subject, action, &tables) {
                    return deny;
                }

                // F27: time-window gates (business hours / freeze windows).
                if let Some(decision) =
                    self.evaluate_time_rules(subject, action, sql, objects, &tables)
                {
                    return decision;
                }

                // S5: high-risk gates (ticket required) before rewrite/mask.
                if let Some(hr) = self.match_high_risk(subject, action, sql, objects, &tables)
                {
                    match self.try_consume_ticket(subject, sql, &hr) {
                        Ok(_ticket_id) => {
                            // Ticket OK — continue with allow path.
                        }
                        Err(message) => {
                            return SecurityDecision::RequireTicket {
                                rule: hr.name.clone(),
                                ticket_type: hr.ticket_type.clone(),
                                message,
                            };
                        }
                    }
                }

                let mut rewritten_sql: Option<String> = None;
                let mut working_sql = sql.clone();

                // Column ACL only when rules mention columns and we have an object set.
                if self.has_column_rules() {
                    if let Some(set) = objects {
                        if !set.parse_failed || !set.objects.is_empty() {
                            match self.evaluate_column_acl(
                                subject,
                                service,
                                action,
                                set,
                                &working_sql,
                            ) {
                                ColumnAclOutcome::Unchanged => {}
                                ColumnAclOutcome::Rewrite { sql: rewritten } => {
                                    working_sql = rewritten.clone();
                                    rewritten_sql = Some(rewritten);
                                }
                                ColumnAclOutcome::Deny { rule, message } => {
                                    return SecurityDecision::Deny { rule, message };
                                }
                            }
                        } else if self.fail_closed {
                            return SecurityDecision::Deny {
                                rule: "fail_closed".into(),
                                message: "security policy deny: column ACL requires parseable SQL (fail_closed)"
                                    .into(),
                            };
                        }
                    }
                }

                let mut obligations = Obligations::default();
                if let Some(max) = self.default_max_rows {
                    obligations.max_rows = Some(max);
                }

                // S3: row_filter from matching allow/deny-adjacent table rules.
                if action == StatementAction::Select {
                    if let Some(filter) = self.collect_row_filter(subject, action, objects, &tables)
                    {
                        match inject_row_filter(&working_sql, &filter) {
                            Some(next) => {
                                rewritten_sql = Some(next);
                                obligations.row_filter = Some(filter);
                            }
                            None if self.fail_closed => {
                                return SecurityDecision::Deny {
                                    rule: "row_filter".into(),
                                    message: format!(
                                        "security policy deny: cannot inject row_filter '{filter}' into SQL"
                                    ),
                                };
                            }
                            None => {}
                        }
                    }
                }

                // S3: column tags → mask obligations (result path).
                if action == StatementAction::Select {
                    let masks = self.collect_mask_specs(subject, objects, &tables, &columns);
                    for m in masks {
                        obligations.column_masks.push(m);
                    }
                }

                // F14: visible watermark on SELECT allows.
                if action == StatementAction::Select {
                    if let Some(wm) = self.build_watermark(subject, service) {
                        obligations.watermark = Some(wm);
                    }
                }

                if let Some(sql) = rewritten_sql {
                    SecurityDecision::AllowRewrite { sql, obligations }
                } else {
                    SecurityDecision::Allow { obligations }
                }
            }
        }
    }

    fn collect_row_filter(
        &self,
        subject: &Subject,
        action: StatementAction,
        objects: Option<&ObjectSet>,
        tables: &[String],
    ) -> Option<String> {
        let mut filters: Vec<String> = Vec::new();
        for rule in &self.rules {
            let Some(filter) = rule.row_filter.as_ref() else {
                continue;
            };
            if filter.trim().is_empty() {
                continue;
            }
            // Row filters apply on allow-path; skip pure deny column rules.
            if !rule.columns.is_empty() && rule.effect.eq_ignore_ascii_case("deny") {
                continue;
            }
            if !subject_matches(rule, subject) {
                continue;
            }
            if !action_matches(rule, action) {
                continue;
            }
            if !rule.tables.is_empty() {
                let matched = if let Some(set) = objects {
                    set.objects.iter().any(|obj| table_matches_rule(rule, obj))
                } else {
                    tables.iter().any(|t| {
                        rule.tables
                            .iter()
                            .any(|p| table_glob_match(p, t))
                    })
                };
                if !matched {
                    continue;
                }
            }
            if !filters.iter().any(|f| f == filter) {
                filters.push(filter.clone());
            }
        }
        if filters.is_empty() {
            None
        } else if filters.len() == 1 {
            Some(filters.remove(0))
        } else {
            Some(
                filters
                    .into_iter()
                    .map(|f| format!("({f})"))
                    .collect::<Vec<_>>()
                    .join(" AND "),
            )
        }
    }

    fn collect_mask_specs(
        &self,
        subject: &Subject,
        objects: Option<&ObjectSet>,
        tables: &[String],
        columns: &[String],
    ) -> Vec<MaskSpec> {
        if self.column_tags.is_empty() || self.mask_rules.is_empty() {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mask_by_name: std::collections::BTreeMap<String, &SecurityMaskRuleConfig> = self
            .mask_rules
            .iter()
            .map(|m| (m.name.to_ascii_lowercase(), m))
            .collect();

        let candidate_columns: Vec<(String, String)> = if let Some(set) = objects {
            let mut pairs = Vec::new();
            for obj in &set.objects {
                for col in obj.bare_columns() {
                    pairs.push((obj.table.clone(), col));
                }
                // Wildcard: still apply tags by configured column names (result meta will match).
                if obj.has_wildcard {
                    for tag in &self.column_tags {
                        let bare = tag
                            .column
                            .rsplit('.')
                            .next()
                            .unwrap_or(tag.column.as_str())
                            .to_ascii_lowercase();
                        pairs.push((obj.table.clone(), bare));
                    }
                }
            }
            if pairs.is_empty() {
                // No projection columns known — still emit tags for result-meta matching.
                for tag in &self.column_tags {
                    let bare = tag
                        .column
                        .rsplit('.')
                        .next()
                        .unwrap_or(tag.column.as_str())
                        .to_ascii_lowercase();
                    let table = tables.first().cloned().unwrap_or_default();
                    pairs.push((table, bare));
                }
            }
            pairs
        } else {
            columns
                .iter()
                .map(|c| {
                    (
                        tables.first().cloned().unwrap_or_default(),
                        c.to_ascii_lowercase(),
                    )
                })
                .collect()
        };

        for (table, col) in candidate_columns {
            for tag in &self.column_tags {
                if !tag.subjects.is_empty() {
                    let sid = subject.subject_id.as_str();
                    if !tag.subjects.iter().any(|p| glob_match(p, sid)) {
                        continue;
                    }
                }
                if !tag.tables.is_empty()
                    && !tag
                        .tables
                        .iter()
                        .any(|p| table_glob_match(p, &table) || table.is_empty())
                {
                    continue;
                }
                if !column_tag_matches(tag, &col, &table) {
                    continue;
                }
                let Some(mask_cfg) = mask_by_name.get(&tag.mask_rule.to_ascii_lowercase()) else {
                    continue;
                };
                let Some(algo) = MaskAlgorithm::parse(&mask_cfg.algorithm) else {
                    continue;
                };
                if out
                    .iter()
                    .any(|m: &MaskSpec| m.column.eq_ignore_ascii_case(&col))
                {
                    continue;
                }
                let mut spec = MaskSpec::new(col.clone(), algo, tag.mask_rule.clone());
                if !mask_cfg.replace_with.is_empty() {
                    spec.replace_with = mask_cfg.replace_with.clone();
                }
                spec.prefix_len = mask_cfg.prefix_len;
                spec.suffix_len = mask_cfg.suffix_len;
                out.push(spec);
            }
        }
        out
    }



    fn build_watermark(&self, subject: &Subject, service: &str) -> Option<WatermarkSpec> {
        if !self.watermark.enabled {
            return None;
        }
        let token = if self.watermark.token.trim().is_empty() {
            // subject|service|millis — demo trace id (not crypto).
            let ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0);
            format!("{}|{}|{:x}", subject.subject_id, service, ms)
        } else {
            self.watermark.token.clone()
        };
        Some(WatermarkSpec {
            mode: WatermarkMode::parse(&self.watermark.mode),
            column: if self.watermark.column.trim().is_empty() {
                "_dn_wm".into()
            } else {
                self.watermark.column.clone()
            },
            token,
        })
    }

    /// F26: Cedar table/action authorization when engine is loaded.
    fn evaluate_cedar(
        &self,
        subject: &Subject,
        action: StatementAction,
        tables: &[String],
    ) -> Option<SecurityDecision> {
        #[cfg(feature = "security-cedar")]
        {
            if !self.cedar_required {
                return None;
            }
            let Some(engine) = self.cedar.as_ref() else {
                return Some(SecurityDecision::Deny {
                    rule: "cedar".into(),
                    message: "cedar PDP failed to load; deny (fail closed)".into(),
                });
            };
            match engine.authorize_tables(&subject.subject_id, action, tables) {
                Ok(()) => None,
                Err(message) => Some(SecurityDecision::Deny {
                    rule: "cedar".into(),
                    message,
                }),
            }
        }
        #[cfg(not(feature = "security-cedar"))]
        {
            let _ = (subject, action, tables);
            None
        }
    }

    /// F27: first matching time rule that is currently active.
    fn evaluate_time_rules(
        &self,
        subject: &Subject,
        action: StatementAction,
        sql: &str,
        objects: Option<&ObjectSet>,
        tables: &[String],
    ) -> Option<SecurityDecision> {
        if self.time_rules.is_empty() {
            return None;
        }
        let now = crate::security_now_unix_secs();
        for tr in &self.time_rules {
            if !tr.subjects.is_empty() {
                let sid = subject.subject_id.as_str();
                if !tr.subjects.iter().any(|p| glob_match(p, sid)) {
                    continue;
                }
            }
            let actions = if tr.actions.is_empty() {
                // Default: writes only (not SELECT).
                vec![
                    "insert".into(),
                    "update".into(),
                    "delete".into(),
                    "ddl".into(),
                ]
            } else {
                tr.actions.clone()
            };
            if !action_matches_actions(&actions, action) {
                continue;
            }
            if !tr.tables.is_empty() {
                let table_hit = if let Some(set) = objects {
                    set.objects.iter().any(|obj| {
                        tr.tables.iter().any(|p| {
                            table_glob_match(p, &obj.qualified_table())
                                || table_glob_match(p, &obj.table)
                        })
                    })
                } else {
                    tables
                        .iter()
                        .any(|t| tr.tables.iter().any(|p| table_glob_match(p, t)))
                };
                if !table_hit {
                    continue;
                }
            }
            if !tr.matches_now(now) {
                continue;
            }
            let msg = if tr.message.trim().is_empty() {
                format!(
                    "security time policy '{}' blocked {} outside allowed window ({}–{} {})",
                    tr.name,
                    action.as_str(),
                    tr.start,
                    tr.end,
                    tr.timezone
                )
            } else {
                format!("security time policy '{}': {}", tr.name, tr.message)
            };
            return Some(match tr.effect.to_ascii_lowercase().as_str() {
                "require_ticket" => {
                    // Reuse ticket path: require an embedded ticket for this SQL.
                    match self.try_consume_time_ticket(subject, sql, tr) {
                        Ok(_) => return None, // ticket OK — continue allow path
                        Err(message) => SecurityDecision::RequireTicket {
                            rule: tr.name.clone(),
                            ticket_type: tr.ticket_type.clone(),
                            message,
                        },
                    }
                }
                _ => SecurityDecision::Deny {
                    rule: tr.name.clone(),
                    message: msg,
                },
            });
        }
        None
    }

    fn try_consume_time_ticket(
        &self,
        subject: &Subject,
        sql: &str,
        tr: &SecurityTimeRuleConfig,
    ) -> Result<String, String> {
        let Some(ticket_id) = extract_ticket_id(sql) else {
            return Err(format!(
                "security time policy '{}': {} (ticket type '{}'; prefix SQL with /*dn_ticket:<id>*/)",
                tr.name,
                if tr.message.trim().is_empty() {
                    "outside allowed time window; ticket required"
                } else {
                    tr.message.as_str()
                },
                tr.ticket_type
            ));
        };
        global_ticket_store()
            .consume(
                &ticket_id,
                &subject.subject_id,
                sql,
                Some(tr.ticket_type.as_str()),
            )
            .map(|t| t.id)
            .map_err(|e| format!("security time policy '{}' ticket rejected: {e}", tr.name))
    }

    fn match_high_risk(
        &self,
        subject: &Subject,
        action: StatementAction,
        sql: &str,
        objects: Option<&ObjectSet>,
        tables: &[String],
    ) -> Option<SecurityHighRiskRuleConfig> {
        for hr in &self.high_risk_rules {
            if !hr.subjects.is_empty() {
                let sid = subject.subject_id.as_str();
                if !hr.subjects.iter().any(|p| glob_match(p, sid)) {
                    continue;
                }
            }
            let kind = hr.kind.to_ascii_lowercase();
            let hit = match kind.as_str() {
                "ddl" => action == StatementAction::Ddl,
                "write_no_where" => is_write_without_where(sql),
                "export" => {
                    let u = strip_ticket_comment(sql).to_ascii_uppercase();
                    u.contains(" INTO OUTFILE")
                        || u.contains("DUMPFILE")
                        || u.starts_with("COPY ")
                        || u.contains(" COPY ")
                }
                "action" => {
                    if hr.actions.is_empty() {
                        false
                    } else {
                        action_matches_actions(&hr.actions, action)
                    }
                }
                "table_write" => {
                    let write = matches!(
                        action,
                        StatementAction::Insert
                            | StatementAction::Update
                            | StatementAction::Delete
                            | StatementAction::Ddl
                    );
                    if !write {
                        false
                    } else if hr.tables.is_empty() {
                        true
                    } else if let Some(set) = objects {
                        set.objects.iter().any(|obj| {
                            hr.tables.iter().any(|p| {
                                table_glob_match(p, &obj.qualified_table())
                                    || table_glob_match(p, &obj.table)
                            })
                        })
                    } else {
                        tables.iter().any(|t| {
                            hr.tables.iter().any(|p| table_glob_match(p, t))
                        })
                    }
                }
                _ => false,
            };
            if hit {
                return Some(hr.clone());
            }
        }
        None
    }

    fn try_consume_ticket(
        &self,
        subject: &Subject,
        sql: &str,
        hr: &SecurityHighRiskRuleConfig,
    ) -> Result<String, String> {
        let Some(ticket_id) = extract_ticket_id(sql) else {
            let hint = if hr.message.trim().is_empty() {
                format!(
                    "security policy '{}' requires ticket type '{}'; re-issue via POST /admin/tickets and prefix SQL with /*dn_ticket:<id>*/",
                    hr.name, hr.ticket_type
                )
            } else {
                format!(
                    "security policy '{}': {} (ticket type '{}'; prefix SQL with /*dn_ticket:<id>*/)",
                    hr.name, hr.message, hr.ticket_type
                )
            };
            return Err(hint);
        };
        global_ticket_store()
            .consume(
                &ticket_id,
                &subject.subject_id,
                sql,
                Some(hr.ticket_type.as_str()),
            )
            .map(|t| t.id)
            .map_err(|e| {
                format!(
                    "security policy '{}' ticket rejected: {e}",
                    hr.name
                )
            })
    }

    /// Apply column deny rules: strip columns from SELECT when possible, else deny.
    pub fn evaluate_column_acl(
        &self,
        subject: &Subject,
        service: &str,
        action: StatementAction,
        objects: &ObjectSet,
        sql: &str,
    ) -> ColumnAclOutcome {
        let mut denied_columns: Vec<(String, String)> = Vec::new(); // (rule, column)

        for rule in &self.rules {
            if rule.columns.is_empty() {
                continue;
            }
            if !subject_matches(rule, subject) {
                continue;
            }
            if !action_matches(rule, action) {
                continue;
            }

            for obj in &objects.objects {
                if !table_matches_rule(rule, obj) {
                    continue;
                }

                if obj.has_wildcard {
                    if self.star_policy == StarPolicy::Deny
                        && rule.effect.eq_ignore_ascii_case("deny")
                    {
                        return ColumnAclOutcome::Deny {
                            rule: rule.name.clone(),
                            message: format!(
                                "security policy '{}' denies wildcard projection on table '{}' (star_policy=deny); list columns explicitly",
                                rule.name,
                                obj.qualified_table()
                            ),
                        };
                    }
                    // star_policy=allow: skip wildcard; only explicit columns below.
                }

                for col in obj.bare_columns() {
                    if column_matches_rule(rule, &col, &obj.table) {
                        match rule.effect.to_ascii_lowercase().as_str() {
                            "deny" => denied_columns.push((rule.name.clone(), col)),
                            "allow" => {}
                            _ => {}
                        }
                    }
                }
            }
        }

        if denied_columns.is_empty() {
            return ColumnAclOutcome::Unchanged;
        }

        // Only attempt rewrite for SELECT with explicit columns.
        if action == StatementAction::Select && !objects.has_wildcard() {
            match rewrite_select_strip_columns(sql, &denied_columns) {
                Some(rewritten) if rewritten != sql => {
                    return ColumnAclOutcome::Rewrite { sql: rewritten };
                }
                Some(_) => {
                    // All columns stripped or rewrite produced empty projection.
                    let (rule, col) = &denied_columns[0];
                    return ColumnAclOutcome::Deny {
                        rule: rule.clone(),
                        message: format!(
                            "security policy '{rule}' denied column '{col}' on service '{service}' (empty projection after strip)"
                        ),
                    };
                }
                None => {
                    let (rule, col) = &denied_columns[0];
                    return ColumnAclOutcome::Deny {
                        rule: rule.clone(),
                        message: format!(
                            "security policy '{rule}' denied column '{col}' on service '{service}' (rewrite not possible)"
                        ),
                    };
                }
            }
        }

        let (rule, col) = &denied_columns[0];
        ColumnAclOutcome::Deny {
            rule: rule.clone(),
            message: format!(
                "security policy '{rule}' denied column '{col}' for {} on service '{service}'",
                action.as_str()
            ),
        }
    }
}

fn collect_bare_columns(set: &ObjectSet) -> Vec<String> {
    let mut out = Vec::new();
    for obj in &set.objects {
        for c in obj.bare_columns() {
            if !out.iter().any(|x: &String| x == &c) {
                out.push(c);
            }
        }
    }
    out
}

fn subject_matches(rule: &SecurityRuleConfig, subject: &Subject) -> bool {
    if rule.subjects.is_empty() {
        return true;
    }
    let sid = subject.subject_id.as_str();
    rule.subjects
        .iter()
        .any(|pattern| glob_match(pattern, sid))
}

fn action_matches_actions(actions: &[String], action: StatementAction) -> bool {
    if actions.is_empty() {
        return true;
    }
    let action_s = action.as_str();
    actions.iter().any(|a| {
        let a = a.to_ascii_lowercase();
        a == action_s
            || a == "*"
            || (a == "write"
                && matches!(
                    action,
                    StatementAction::Insert
                        | StatementAction::Update
                        | StatementAction::Delete
                        | StatementAction::Ddl
                ))
            || (a == "read" && action == StatementAction::Select)
            || (a == "dml"
                && matches!(
                    action,
                    StatementAction::Insert | StatementAction::Update | StatementAction::Delete
                ))
    })
}

fn action_matches(rule: &SecurityRuleConfig, action: StatementAction) -> bool {
    if rule.actions.is_empty() {
        return true;
    }
    let action_s = action.as_str();
    rule.actions.iter().any(|a| {
        let a = a.to_ascii_lowercase();
        a == action_s
            || a == "*"
            || (a == "write"
                && matches!(
                    action,
                    StatementAction::Insert
                        | StatementAction::Update
                        | StatementAction::Delete
                        | StatementAction::Ddl
                ))
            || (a == "read" && action == StatementAction::Select)
            || (a == "dml"
                && matches!(
                    action,
                    StatementAction::Insert | StatementAction::Update | StatementAction::Delete
                ))
    })
}

fn table_matches_rule(
    rule: &SecurityRuleConfig,
    obj: &crate::object_set::ObjectAccess,
) -> bool {
    if rule.tables.is_empty() {
        return true;
    }
    let qualified = obj.qualified_table();
    rule.tables.iter().any(|pattern| {
        table_glob_match(pattern, &qualified) || table_glob_match(pattern, &obj.table)
    })
}

fn column_matches_rule(rule: &SecurityRuleConfig, bare_col: &str, table: &str) -> bool {
    rule.columns.iter().any(|pattern| {
        let p = pattern.trim();
        if p.contains('.') {
            // table.col or *.col
            let mut parts = p.rsplitn(2, '.');
            let col_pat = parts.next().unwrap_or("");
            let tbl_pat = parts.next().unwrap_or("*");
            glob_match(col_pat, bare_col)
                && (tbl_pat == "*" || glob_match(tbl_pat, table))
        } else {
            glob_match(p, bare_col)
        }
    })
}

fn column_tag_matches(tag: &SecurityColumnTagConfig, bare_col: &str, table: &str) -> bool {
    let p = tag.column.trim();
    if p.contains('.') {
        let mut parts = p.rsplitn(2, '.');
        let col_pat = parts.next().unwrap_or("");
        let tbl_pat = parts.next().unwrap_or("*");
        glob_match(col_pat, bare_col) && (tbl_pat == "*" || glob_match(tbl_pat, table))
    } else {
        glob_match(p, bare_col)
    }
}

fn rule_matches(rule: &SecurityRuleConfig, request: &AccessRequest<'_>) -> bool {
    if !subject_matches(rule, request.subject) {
        return false;
    }
    if !action_matches(rule, request.action) {
        return false;
    }

    if !rule.tables.is_empty() {
        if request.tables.is_empty() {
            // Rule requires tables but none extracted → no match (avoid false deny on SELECT 1).
            return false;
        }
        let matched = request.tables.iter().any(|table| {
            rule.tables
                .iter()
                .any(|pattern| table_glob_match(pattern, table))
        });
        if !matched {
            return false;
        }
    }

    let _ = request.service;
    true
}

fn table_glob_match(pattern: &str, table: &str) -> bool {
    let table = table.trim_matches('`').trim_matches('"').trim_matches('\'');
    if glob_match(pattern, table) {
        return true;
    }
    // Match bare name against last segment: schema.table / catalog.schema.table
    if let Some(base) = table.rsplit('.').next() {
        if base != table && glob_match(pattern, base) {
            return true;
        }
        if glob_match(pattern, table) {
            return true;
        }
    }
    // Pattern may be only the leaf: secret_*
    if let Some(leaf) = pattern.rsplit('.').next() {
        if leaf != pattern {
            if let Some(base) = table.rsplit('.').next() {
                return glob_match(leaf, base);
            }
        }
    }
    false
}

/// Glob with `*` (any run) and `?` (one char). Case-insensitive for SQL ids.
pub(crate) fn glob_match(pattern: &str, value: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    let value = value.to_ascii_lowercase();
    glob_match_bytes(pattern.as_bytes(), value.as_bytes())
}

fn glob_match_bytes(pattern: &[u8], value: &[u8]) -> bool {
    let (mut pi, mut vi) = (0usize, 0usize);
    let mut star_p = None;
    let mut star_v = 0usize;
    while vi < value.len() {
        if pi < pattern.len() && (pattern[pi] == b'?' || pattern[pi] == value[vi]) {
            pi += 1;
            vi += 1;
        } else if pi < pattern.len() && pattern[pi] == b'*' {
            star_p = Some(pi);
            star_v = vi;
            pi += 1;
        } else if let Some(sp) = star_p {
            pi = sp + 1;
            star_v += 1;
            vi = star_v;
        } else {
            return false;
        }
    }
    while pi < pattern.len() && pattern[pi] == b'*' {
        pi += 1;
    }
    pi == pattern.len()
}

/// Best-effort table name extraction for S1 / parse fallback (not a full SQL parser).
pub fn extract_table_names(sql: &str) -> Vec<String> {
    let mut tables = Vec::new();
    let upper = sql.to_ascii_uppercase();
    let bytes = sql.as_bytes();
    let upper_bytes = upper.as_bytes();

    for keyword in [
        " FROM ",
        " JOIN ",
        " INTO ",
        " UPDATE ",
        " TABLE ",
        "\nFROM ",
        "\nJOIN ",
        "\nINTO ",
        "\nUPDATE ",
        "\nTABLE ",
    ] {
        let mut start = 0usize;
        let key = keyword.as_bytes();
        while let Some(rel) = find_slice(&upper_bytes[start..], key) {
            let after = start + rel + key.len();
            if let Some(name) = next_sql_ident(&sql[after..]) {
                push_unique(&mut tables, name);
            }
            start = after;
        }
    }

    let trimmed = sql.trim_start();
    let trimmed_upper = trimmed.to_ascii_uppercase();
    for prefix in [
        "UPDATE ",
        "INSERT INTO ",
        "DELETE FROM ",
        "TRUNCATE TABLE ",
        "TRUNCATE ",
    ] {
        if let Some(rest) = trimmed_upper.strip_prefix(prefix) {
            let offset = prefix.len();
            if let Some(name) = next_sql_ident(
                &trimmed[offset..offset + rest.len().min(trimmed.len() - offset)],
            ) {
                push_unique(&mut tables, name);
            }
        }
    }

    let _ = bytes;
    tables
}

fn find_slice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn next_sql_ident(input: &str) -> Option<String> {
    let s = input.trim_start();
    if s.is_empty() {
        return None;
    }
    let mut chars = s.chars().peekable();
    let mut out = String::new();
    match chars.peek().copied() {
        Some('`') | Some('"') | Some('\'') => {
            let q = chars.next()?;
            for c in chars.by_ref() {
                if c == q {
                    break;
                }
                out.push(c);
            }
        }
        Some(c) if c.is_ascii_alphanumeric() || c == '_' || c == '$' => {
            out.push(c);
            chars.next();
            for c in chars.by_ref() {
                if c.is_ascii_alphanumeric() || c == '_' || c == '$' || c == '.' {
                    out.push(c);
                } else {
                    break;
                }
            }
        }
        _ => return None,
    }
    let name = out.trim().trim_matches('.').to_owned();
    if name.is_empty()
        || matches!(
            name.to_ascii_uppercase().as_str(),
            "SELECT"
                | "WHERE"
                | "SET"
                | "VALUES"
                | "ON"
                | "AS"
                | "LEFT"
                | "RIGHT"
                | "INNER"
                | "OUTER"
                | "CROSS"
                | "ONLY"
        )
    {
        return None;
    }
    Some(name)
}

fn push_unique(tables: &mut Vec<String>, name: String) {
    if !tables.iter().any(|t| t.eq_ignore_ascii_case(&name)) {
        tables.push(name);
    }
}

/// Strip denied columns from a simple SELECT list (heuristic, no full AST rewrite).
///
/// Returns `None` when the SQL shape is not a simple SELECT list rewrite target.
/// Returns `Some` rewritten SQL (may have empty projection → caller should deny).
fn rewrite_select_strip_columns(sql: &str, denied: &[(String, String)]) -> Option<String> {
    if denied.is_empty() {
        return Some(sql.to_owned());
    }
    let trimmed = sql.trim_start();
    let upper = trimmed.to_ascii_uppercase();
    if !upper.starts_with("SELECT") {
        return None;
    }
    let after_select = trimmed[6..].trim_start();
    // Optional DISTINCT
    let after_select = if after_select.to_ascii_uppercase().starts_with("DISTINCT") {
        after_select[8..].trim_start()
    } else {
        after_select
    };

    let from_idx = find_top_level_keyword(after_select, "FROM")?;
    let select_list = after_select[..from_idx].trim();
    let rest = &after_select[from_idx..]; // starts with FROM ...

    if select_list == "*" || select_list.ends_with(".*") {
        return None;
    }

    let parts = split_select_list(select_list);
    if parts.is_empty() {
        return None;
    }

    let denied_names: Vec<String> = denied.iter().map(|(_, c)| c.to_ascii_lowercase()).collect();
    let kept: Vec<&str> = parts
        .iter()
        .copied()
        .filter(|part| {
            let bare = select_item_bare_name(part);
            !denied_names.iter().any(|d| d == &bare)
        })
        .collect();

    if kept.is_empty() {
        // Signal empty projection with a sentinel rewrite the caller treats as deny.
        return Some(format!("SELECT {rest}"));
    }

    let new_list = kept.join(", ");
    // Preserve leading whitespace / casing of SELECT keyword region lightly.
    let prefix_end = sql.len() - trimmed.len();
    let mut out = String::new();
    out.push_str(&sql[..prefix_end]);
    out.push_str("SELECT ");
    if upper[6..].trim_start().starts_with("DISTINCT") {
        out.push_str("DISTINCT ");
    }
    out.push_str(&new_list);
    out.push(' ');
    out.push_str(rest.trim_start());
    Some(out)
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

fn split_select_list(list: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut depth = 0i32;
    let mut in_single = false;
    let mut in_double = false;
    let mut in_back = false;
    let bytes = list.as_bytes();
    for (i, &c) in bytes.iter().enumerate() {
        if in_single {
            if c == b'\'' {
                in_single = false;
            }
            continue;
        }
        if in_double {
            if c == b'"' {
                in_double = false;
            }
            continue;
        }
        if in_back {
            if c == b'`' {
                in_back = false;
            }
            continue;
        }
        match c {
            b'\'' => in_single = true,
            b'"' => in_double = true,
            b'`' => in_back = true,
            b'(' => depth += 1,
            b')' => depth -= 1,
            b',' if depth == 0 => {
                let part = list[start..i].trim();
                if !part.is_empty() {
                    parts.push(part);
                }
                start = i + 1;
            }
            _ => {}
        }
    }
    let part = list[start..].trim();
    if !part.is_empty() {
        parts.push(part);
    }
    parts
}

fn select_item_bare_name(item: &str) -> String {
    // take last identifier before AS alias or end
    let upper = item.to_ascii_uppercase();
    let expr = if let Some(idx) = find_top_level_keyword(item, "AS") {
        item[..idx].trim()
    } else {
        // trailing alias without AS: "col alias"
        let tokens: Vec<&str> = item.split_whitespace().collect();
        if tokens.len() >= 2 && !tokens[0].contains('(') {
            tokens[0]
        } else {
            item.trim()
        }
    };
    let _ = upper;
    let bare = expr
        .rsplit('.')
        .next()
        .unwrap_or(expr)
        .trim_matches('`')
        .trim_matches('"')
        .trim_matches('\'');
    bare.to_ascii_lowercase()
}

/// Helper for tests / callers using CommandSummary.
pub fn sql_from_command(command: &GatewayCommand) -> Option<&str> {
    match command {
        GatewayCommand::Query { sql } | GatewayCommand::Prepare { sql } => Some(sql.as_str()),
        _ => None,
    }
}

pub fn action_from_command(command: &GatewayCommand, dialect: &dyn DialectParser) -> StatementAction {
    match command {
        GatewayCommand::Begin | GatewayCommand::Commit | GatewayCommand::Rollback => {
            StatementAction::Tcl
        }
        GatewayCommand::Query { sql } | GatewayCommand::Prepare { sql } => dialect
            .leading_keyword(sql)
            .map(|k| StatementAction::from_keyword(&k))
            .unwrap_or(StatementAction::Other),
        GatewayCommand::UseDatabase { .. } => StatementAction::Other,
        _ => StatementAction::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object_set::{ObjectAccess, ObjectSet};
    use crate::{HeuristicDialectParser, ProtocolKind};

    fn pdp_with(rules: Vec<SecurityRuleConfig>) -> LocalPdp {
        LocalPdp {
            fail_closed: true,
            star_policy: StarPolicy::Deny,
            rules,
            mask_rules: Vec::new(),
            column_tags: Vec::new(),
            high_risk_rules: Vec::new(),
            time_rules: Vec::new(),
            default_max_rows: None,
            watermark: SecurityWatermarkConfig::default(),

            #[cfg(feature = "security-cedar")]
            cedar: None,
            #[cfg(feature = "security-cedar")]
            cedar_required: false,
        }
    }

    fn subject(user: &str) -> Subject {
        Subject::from_protocol_user(Some(user), Some("orders"))
    }

    #[test]
    fn disabled_config_yields_no_pdp() {
        let cfg = SecurityPolicyConfig::default();
        assert!(LocalPdp::from_config(&cfg).is_none());
    }

    #[test]
    fn deny_secret_table_select() {
        let pdp = pdp_with(vec![SecurityRuleConfig {
            name: "deny-secret".into(),
            effect: "deny".into(),
            actions: vec!["select".into()],
            tables: vec!["secret_*".into()],
            columns: vec![],
            subjects: vec![],
            row_filter: None,
        }]);
        let sub = subject("app");
        let dialect = HeuristicDialectParser::new(ProtocolKind::MySql);
        let cmd = GatewayCommand::Query {
            sql: "SELECT * FROM secret_tokens WHERE id=1".into(),
        };
        assert!(pdp
            .authorize_command(&sub, "orders", &cmd, &dialect)
            .is_deny());
    }

    #[test]
    fn allow_when_table_not_matched() {
        let pdp = pdp_with(vec![SecurityRuleConfig {
            name: "deny-secret".into(),
            effect: "deny".into(),
            actions: vec!["select".into()],
            tables: vec!["secret_*".into()],
            columns: vec![],
            subjects: vec![],
            row_filter: None,
        }]);
        let sub = subject("app");
        let dialect = HeuristicDialectParser::new(ProtocolKind::MySql);
        let cmd = GatewayCommand::Query {
            sql: "SELECT 1".into(),
        };
        assert!(!pdp
            .authorize_command(&sub, "orders", &cmd, &dialect)
            .is_deny());
    }

    #[test]
    fn deny_ddl_for_subject() {
        let pdp = pdp_with(vec![SecurityRuleConfig {
            name: "no-ddl-analyst".into(),
            effect: "deny".into(),
            actions: vec!["ddl".into()],
            tables: vec![],
            columns: vec![],
            subjects: vec!["analyst".into()],
            row_filter: None,
        }]);
        let sub = subject("analyst");
        let dialect = HeuristicDialectParser::new(ProtocolKind::PostgreSql);
        let cmd = GatewayCommand::Query {
            sql: "CREATE TABLE t (id int)".into(),
        };
        assert!(pdp
            .authorize_command(&sub, "analytics", &cmd, &dialect)
            .is_deny());
        let app = subject("app");
        assert!(!pdp
            .authorize_command(&app, "analytics", &cmd, &dialect)
            .is_deny());
    }

    #[test]
    fn extract_from_join() {
        let tables = extract_table_names(
            "SELECT a.id FROM orders a JOIN order_items b ON a.id=b.order_id",
        );
        assert!(tables.iter().any(|t| t.eq_ignore_ascii_case("orders")));
        assert!(tables.iter().any(|t| t.eq_ignore_ascii_case("order_items")));
    }

    #[test]
    fn glob_star() {
        assert!(glob_match("secret_*", "secret_tokens"));
        assert!(!glob_match("secret_*", "public_tokens"));
        assert!(glob_match("*.secret_*", "app.secret_keys"));
    }

    #[test]
    fn subject_anonymous_when_missing_user() {
        let s = Subject::from_protocol_user(None, None);
        assert_eq!(s.subject_id, "anonymous");
    }

    #[test]
    fn command_summary_not_required_for_authorize() {
        let _ = CommandSummary::from_command(&GatewayCommand::Ping);
    }

    #[test]
    fn column_deny_rewrites_select_list() {
        let pdp = pdp_with(vec![SecurityRuleConfig {
            name: "deny-salary".into(),
            effect: "deny".into(),
            actions: vec!["select".into()],
            tables: vec!["employees".into()],
            columns: vec!["salary".into(), "ssn".into()],
            subjects: vec![],
            row_filter: None,
        }]);
        let mut set = ObjectSet::empty();
        let mut obj = ObjectAccess::new("employees", StatementAction::Select);
        obj.columns = vec!["id".into(), "name".into(), "salary".into()];
        set.objects.push(obj);

        let sub = subject("app");
        let dialect = HeuristicDialectParser::mysql();
        let cmd = GatewayCommand::Query {
            sql: "SELECT id, name, salary FROM employees".into(),
        };
        match pdp.authorize_command_with_objects(&sub, "hr", &cmd, &dialect, Some(&set)) {
            SecurityDecision::AllowRewrite { sql, .. } => {
                assert!(sql.to_ascii_lowercase().contains("id"));
                assert!(sql.to_ascii_lowercase().contains("name"));
                assert!(!sql.to_ascii_lowercase().contains("salary"));
            }
            other => panic!("expected rewrite, got {other:?}"),
        }
    }

    #[test]
    fn column_deny_wildcard_with_star_policy_deny() {
        let pdp = pdp_with(vec![SecurityRuleConfig {
            name: "deny-salary".into(),
            effect: "deny".into(),
            actions: vec!["select".into()],
            tables: vec!["employees".into()],
            columns: vec!["salary".into()],
            subjects: vec![],
            row_filter: None,
        }]);
        let mut set = ObjectSet::empty();
        let mut obj = ObjectAccess::new("employees", StatementAction::Select);
        obj.has_wildcard = true;
        set.objects.push(obj);
        let sub = subject("app");
        let dialect = HeuristicDialectParser::mysql();
        let cmd = GatewayCommand::Query {
            sql: "SELECT * FROM employees".into(),
        };
        assert!(pdp
            .authorize_command_with_objects(&sub, "hr", &cmd, &dialect, Some(&set))
            .is_deny());
    }

    #[test]
    fn parse_failed_fail_closed() {
        let pdp = pdp_with(vec![SecurityRuleConfig {
            name: "deny-secret".into(),
            effect: "deny".into(),
            actions: vec!["select".into()],
            tables: vec!["secret_*".into()],
            columns: vec![],
            subjects: vec![],
            row_filter: None,
        }]);
        let set = ObjectSet::parse_failed();
        let sub = subject("app");
        let dialect = HeuristicDialectParser::mysql();
        let cmd = GatewayCommand::Query {
            sql: "SELECT !!!".into(),
        };
        assert!(pdp
            .authorize_command_with_objects(&sub, "orders", &cmd, &dialect, Some(&set))
            .is_deny());
    }

    #[test]
    fn rewrite_strips_multiple_columns() {
        let denied = vec![
            ("r".into(), "salary".into()),
            ("r".into(), "ssn".into()),
        ];
        let sql = "SELECT id, salary, name, ssn FROM employees WHERE id=1";
        let out = rewrite_select_strip_columns(sql, &denied).unwrap();
        let lower = out.to_ascii_lowercase();
        assert!(lower.contains("id"));
        assert!(lower.contains("name"));
        assert!(!lower.contains("salary"));
        assert!(!lower.contains("ssn"));
        assert!(lower.contains("from employees"));
    }

    #[test]
    fn row_filter_injects_where() {
        let pdp = LocalPdp {
            fail_closed: true,
            star_policy: StarPolicy::Deny,
            rules: vec![SecurityRuleConfig {
                name: "tenant-row".into(),
                effect: "allow".into(),
                actions: vec!["select".into()],
                tables: vec!["employees".into()],
                columns: vec![],
                subjects: vec![],
                row_filter: Some("tenant_id = 1".into()),
            }],
            mask_rules: Vec::new(),
            column_tags: Vec::new(),
            high_risk_rules: Vec::new(),
            time_rules: Vec::new(),
            default_max_rows: None,
            watermark: SecurityWatermarkConfig::default(),

            #[cfg(feature = "security-cedar")]
            cedar: None,
            #[cfg(feature = "security-cedar")]
            cedar_required: false,
        };
        let mut set = ObjectSet::empty();
        let mut obj = ObjectAccess::new("employees", StatementAction::Select);
        obj.columns = vec!["id".into(), "name".into()];
        set.objects.push(obj);
        let sub = subject("app");
        let dialect = HeuristicDialectParser::mysql();
        let cmd = GatewayCommand::Query {
            sql: "SELECT id, name FROM employees".into(),
        };
        match pdp.authorize_command_with_objects(&sub, "hr", &cmd, &dialect, Some(&set)) {
            SecurityDecision::AllowRewrite { sql, obligations } => {
                assert!(sql.to_ascii_lowercase().contains("tenant_id = 1"));
                assert_eq!(obligations.row_filter.as_deref(), Some("tenant_id = 1"));
            }
            other => panic!("expected rewrite with row filter, got {other:?}"),
        }
    }

    #[test]
    fn mask_tags_produce_obligations() {
        use crate::{SecurityColumnTagConfig, SecurityMaskRuleConfig};
        let pdp = LocalPdp {
            fail_closed: true,
            star_policy: StarPolicy::Allow,
            rules: Vec::new(),
            mask_rules: vec![SecurityMaskRuleConfig {
                name: "phone-partial".into(),
                algorithm: "partial".into(),
                replace_with: String::new(),
                prefix_len: 3,
                suffix_len: 2,
            }],
            column_tags: vec![SecurityColumnTagConfig {
                column: "phone".into(),
                tables: vec!["employees".into()],
                subjects: vec![],
                mask_rule: "phone-partial".into(),
                label: "PII".into(),
            }],
            high_risk_rules: Vec::new(),
            time_rules: Vec::new(),
            default_max_rows: None,
            watermark: SecurityWatermarkConfig::default(),

            #[cfg(feature = "security-cedar")]
            cedar: None,
            #[cfg(feature = "security-cedar")]
            cedar_required: false,
        };
        let mut set = ObjectSet::empty();
        let mut obj = ObjectAccess::new("employees", StatementAction::Select);
        obj.columns = vec!["id".into(), "phone".into()];
        set.objects.push(obj);
        let sub = subject("app");
        let dialect = HeuristicDialectParser::mysql();
        let cmd = GatewayCommand::Query {
            sql: "SELECT id, phone FROM employees".into(),
        };
        match pdp.authorize_command_with_objects(&sub, "hr", &cmd, &dialect, Some(&set)) {
            SecurityDecision::Allow { obligations } => {
                assert_eq!(obligations.column_masks.len(), 1);
                assert_eq!(obligations.column_masks[0].column.to_ascii_lowercase(), "phone");
            }
            other => panic!("expected allow with masks, got {other:?}"),
        }
    }

    #[test]
    fn high_risk_requires_ticket_then_allows() {
        use crate::{global_ticket_store, IssueTicketRequest, SecurityHighRiskRuleConfig};
        let pdp = LocalPdp {
            fail_closed: true,
            star_policy: StarPolicy::Deny,
            rules: Vec::new(),
            mask_rules: Vec::new(),
            column_tags: Vec::new(),
            high_risk_rules: vec![SecurityHighRiskRuleConfig {
                name: "require-ddl-ticket".into(),
                kind: "ddl".into(),
                ticket_type: "ddl".into(),
                actions: vec![],
                tables: vec![],
                subjects: vec![],
                message: "DDL needs approval".into(),
            }],
            time_rules: Vec::new(),
            default_max_rows: None,
            watermark: SecurityWatermarkConfig::default(),

            #[cfg(feature = "security-cedar")]
            cedar: None,
            #[cfg(feature = "security-cedar")]
            cedar_required: false,
        };
        let sub = subject("root");
        let dialect = HeuristicDialectParser::mysql();
        let sql = "DROP TABLE smoke_t";
        let cmd = GatewayCommand::Query { sql: sql.into() };
        match pdp.authorize_command(&sub, "orders", &cmd, &dialect) {
            SecurityDecision::RequireTicket { ticket_type, .. } => {
                assert_eq!(ticket_type, "ddl");
            }
            other => panic!("expected RequireTicket, got {other:?}"),
        }
        let tkt = global_ticket_store().issue(IssueTicketRequest {
            subject_id: "root".into(),
            sql: sql.into(),
            ticket_type: "ddl".into(),
            ttl_secs: 120,
            max_uses: 1,
            note: None,
            issued_by: Some("test".into()),
            dual_control: false,
        });
        let tagged = format!("/*dn_ticket:{}*/ {sql}", tkt.id);
        let cmd2 = GatewayCommand::Query { sql: tagged };
        assert!(
            !pdp.authorize_command(&sub, "orders", &cmd2, &dialect)
                .is_deny()
        );
    }

    #[test]
    fn time_rule_denies_writes_outside_window() {
        use crate::SecurityTimeRuleConfig;
        use std::sync::Mutex;
        // Serialize env mutation for this test process.
        static LOCK: Mutex<()> = Mutex::new(());
        let _g = LOCK.lock().unwrap();
        let ts_out = chrono::DateTime::parse_from_rfc3339("2026-07-17T20:00:00Z")
            .unwrap()
            .timestamp();
        let ts_in = chrono::DateTime::parse_from_rfc3339("2026-07-17T10:00:00Z")
            .unwrap()
            .timestamp();
        std::env::set_var("DATA_NEXUS_SECURITY_NOW_UNIX", ts_out.to_string());

        let pdp = LocalPdp {
            fail_closed: true,
            star_policy: StarPolicy::Allow,
            rules: Vec::new(),
            mask_rules: Vec::new(),
            column_tags: Vec::new(),
            high_risk_rules: Vec::new(),
            time_rules: vec![SecurityTimeRuleConfig {
                name: "work-hours-writes".into(),
                effect: "deny".into(),
                outside: true,
                days: vec![
                    "mon".into(),
                    "tue".into(),
                    "wed".into(),
                    "thu".into(),
                    "fri".into(),
                ],
                start: "09:00".into(),
                end: "18:00".into(),
                timezone: "UTC".into(),
                actions: vec![
                    "insert".into(),
                    "update".into(),
                    "delete".into(),
                    "ddl".into(),
                ],
                subjects: vec![],
                tables: vec![],
                ticket_type: "high_risk".into(),
                message: "writes only during business hours".into(),
            }],
            default_max_rows: None,
            watermark: SecurityWatermarkConfig::default(),

            #[cfg(feature = "security-cedar")]
            cedar: None,
            #[cfg(feature = "security-cedar")]
            cedar_required: false,
        };
        let sub = subject("root");
        let dialect = HeuristicDialectParser::mysql();
        let sel = GatewayCommand::Query {
            sql: "SELECT 1".into(),
        };
        assert!(
            !pdp
                .authorize_command(&sub, "orders", &sel, &dialect)
                .is_deny()
        );
        let ins = GatewayCommand::Query {
            sql: "INSERT INTO t VALUES (1)".into(),
        };
        match pdp.authorize_command(&sub, "orders", &ins, &dialect) {
            SecurityDecision::Deny { rule, message } => {
                assert_eq!(rule, "work-hours-writes");
                assert!(
                    message.to_ascii_lowercase().contains("business")
                        || message.contains("work-hours"),
                    "{message}"
                );
            }
            other => panic!("expected Deny, got {other:?}"),
        }
        std::env::set_var("DATA_NEXUS_SECURITY_NOW_UNIX", ts_in.to_string());
        assert!(
            !pdp
                .authorize_command(&sub, "orders", &ins, &dialect)
                .is_deny()
        );
        std::env::remove_var("DATA_NEXUS_SECURITY_NOW_UNIX");
    }

}

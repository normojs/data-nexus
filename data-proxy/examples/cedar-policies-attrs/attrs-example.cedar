// Data Nexus F29 — attribute-based Cedar sample (tenant / clearance).
// Requires security.pdp.subject_attrs / table_attrs in gateway config.
//
// Entity model:
//   User::"<subject>"  attrs: tenant, clearance, roles (set)
//   Table::"<name>"    attrs: tenant, clearance, classification
//   Action::"select|..."
//
// Example config fragment:
//
// [security.pdp]
// backend = "cedar"
// policy_dir = "examples/cedar-policies-attrs"
// [[security.pdp.subject_attrs]]
// subject_id = "alice"
// tenant = "acme"
// clearance = "secret"
// [[security.pdp.table_attrs]]
// table = "payroll"
// tenant = "acme"
// clearance = "secret"
// classification = "pii"

// Non-sensitive tables: uid-only allow (works even without attr dirs).
permit (
  principal,
  action == Action::"select",
  resource
)
when {
  resource != Table::"payroll" &&
  resource != Table::"secret_tokens"
};

permit (
  principal,
  action == Action::"select",
  resource == Table::"__none__"
);

// Attribute gate: same tenant + principal.clearance == "secret".
permit (
  principal,
  action == Action::"select",
  resource
)
when {
  resource == Table::"payroll" &&
  principal has clearance &&
  principal.clearance == "secret" &&
  principal has tenant &&
  resource has tenant &&
  principal.tenant == resource.tenant
};

forbid (
  principal,
  action,
  resource
)
when { resource == Table::"secret_tokens" };

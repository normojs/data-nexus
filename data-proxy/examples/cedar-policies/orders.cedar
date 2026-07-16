// Data Nexus F26 — sample Cedar policies for table/action authorization.
// Entity model:
//   User::"<subject>"  Action::"select|insert|..."  Table::"<name>"
// Empty object sets use Table::"__none__".

// Allow SELECT on any table except secret_tokens (forbid below wins on secret).
permit (
  principal,
  action == Action::"select",
  resource
);

// SELECT 1 / no tables
permit (
  principal,
  action == Action::"select",
  resource == Table::"__none__"
);

// Explicit forbid for secret tables (overrides permit).
forbid (
  principal,
  action,
  resource
)
when { resource == Table::"secret_tokens" };

// Allow DML on portal demo table only (smoke uses portal_t / smoke tables carefully).
permit (
  principal,
  action == Action::"insert",
  resource == Table::"portal_t"
);

permit (
  principal,
  action == Action::"update",
  resource == Table::"portal_t"
);

permit (
  principal,
  action == Action::"delete",
  resource == Table::"portal_t"
);

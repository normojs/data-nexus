use crate::ProtocolKind;

/// Protocol-neutral logical SQL type used for cross-protocol result mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CanonicalDataType {
    Bool,
    Int8,
    Int16,
    Int32,
    Int64,
    UInt64,
    Float32,
    Float64,
    Decimal,
    String,
    Bytes,
    Date,
    Time,
    Timestamp,
    Timestamptz,
    Json,
    Unknown,
}

impl CanonicalDataType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bool => "bool",
            Self::Int8 => "int8",
            Self::Int16 => "int16",
            Self::Int32 => "int32",
            Self::Int64 => "int64",
            Self::UInt64 => "uint64",
            Self::Float32 => "float32",
            Self::Float64 => "float64",
            Self::Decimal => "decimal",
            Self::String => "string",
            Self::Bytes => "bytes",
            Self::Date => "date",
            Self::Time => "time",
            Self::Timestamp => "timestamp",
            Self::Timestamptz => "timestamptz",
            Self::Json => "json",
            Self::Unknown => "unknown",
        }
    }

    /// Frontend/backend wire type name for resultset metadata.
    pub fn to_protocol_type(self, protocol: &ProtocolKind) -> &'static str {
        match (self, protocol) {
            (Self::Bool, ProtocolKind::MySql) => "tiny",
            (Self::Bool, ProtocolKind::PostgreSql) => "bool",
            (Self::Int8, ProtocolKind::MySql) => "tiny",
            (Self::Int8, ProtocolKind::PostgreSql) => "int2",
            (Self::Int16, ProtocolKind::MySql) => "short",
            (Self::Int16, ProtocolKind::PostgreSql) => "int2",
            (Self::Int32, ProtocolKind::MySql) => "long",
            (Self::Int32, ProtocolKind::PostgreSql) => "int4",
            (Self::Int64, ProtocolKind::MySql) => "longlong",
            (Self::Int64, ProtocolKind::PostgreSql) => "int8",
            (Self::UInt64, ProtocolKind::MySql) => "longlong",
            (Self::UInt64, ProtocolKind::PostgreSql) => "numeric",
            (Self::Float32, ProtocolKind::MySql) => "float",
            (Self::Float32, ProtocolKind::PostgreSql) => "float4",
            (Self::Float64, ProtocolKind::MySql) => "double",
            (Self::Float64, ProtocolKind::PostgreSql) => "float8",
            (Self::Decimal, ProtocolKind::MySql) => "new_decimal",
            (Self::Decimal, ProtocolKind::PostgreSql) => "numeric",
            (Self::String, ProtocolKind::MySql) => "var_string",
            (Self::String, ProtocolKind::PostgreSql) => "text",
            (Self::Bytes, ProtocolKind::MySql) => "blob",
            (Self::Bytes, ProtocolKind::PostgreSql) => "bytea",
            (Self::Date, _) => "date",
            (Self::Time, _) => "time",
            (Self::Timestamp, ProtocolKind::MySql) => "datetime",
            (Self::Timestamp, ProtocolKind::PostgreSql) => "timestamp",
            (Self::Timestamptz, ProtocolKind::MySql) => "timestamp",
            (Self::Timestamptz, ProtocolKind::PostgreSql) => "timestamptz",
            (Self::Json, ProtocolKind::MySql) => "var_string",
            (Self::Json, ProtocolKind::PostgreSql) => "text",
            (Self::Unknown, ProtocolKind::MySql) => "var_string",
            (Self::Unknown, ProtocolKind::PostgreSql) => "text",
        }
    }
}

/// Normalize a backend-reported type name into a canonical type.
pub fn parse_backend_type(data_type: &str, backend: &ProtocolKind) -> CanonicalDataType {
    let t = data_type.to_ascii_lowercase();
    let t = t.trim();

    // Common aliases across drivers / wire layers.
    match t {
        "bool" | "boolean" | "bit" => CanonicalDataType::Bool,
        "tiny" | "tinyint" | "int1" => CanonicalDataType::Int8,
        "short" | "int2" | "smallint" | "year" => CanonicalDataType::Int16,
        "long" | "int" | "int4" | "integer" | "mediumint" => CanonicalDataType::Int32,
        "longlong" | "int8" | "bigint" | "serial" | "bigserial" => CanonicalDataType::Int64,
        "uint64" | "ulonglong" => CanonicalDataType::UInt64,
        "float" | "float4" | "real" => CanonicalDataType::Float32,
        "double" | "float8" | "double precision" => CanonicalDataType::Float64,
        "decimal" | "numeric" | "new_decimal" | "newdecimal" => CanonicalDataType::Decimal,
        "date" => CanonicalDataType::Date,
        "time" => CanonicalDataType::Time,
        "datetime" | "timestamp" => CanonicalDataType::Timestamp,
        "timestamptz" | "timestamp with time zone" => CanonicalDataType::Timestamptz,
        "blob" | "bytea" | "bytes" | "binary" | "varbinary" | "longblob" | "mediumblob"
        | "tinyblob" => CanonicalDataType::Bytes,
        "json" | "jsonb" => CanonicalDataType::Json,
        "text" | "varchar" | "char" | "bpchar" | "var_string" | "string" | "enum" | "set"
        | "uuid" | "name" | "citext" => CanonicalDataType::String,
        other => match backend {
            ProtocolKind::MySql => parse_mysql_specific(other),
            ProtocolKind::PostgreSql => parse_postgresql_specific(other),
        },
    }
}

fn parse_mysql_specific(t: &str) -> CanonicalDataType {
    if t.starts_with("mysql_type_") {
        return parse_backend_type(t.trim_start_matches("mysql_type_"), &ProtocolKind::MySql);
    }
    CanonicalDataType::Unknown
}

fn parse_postgresql_specific(t: &str) -> CanonicalDataType {
    if t.parse::<i32>().is_ok() {
        // OID left as unknown; frontend will present as text/string.
        return CanonicalDataType::Unknown;
    }
    CanonicalDataType::Unknown
}

/// Map a backend column type name to the frontend protocol type name.
pub fn map_column_type(
    backend_type: &str,
    backend: &ProtocolKind,
    frontend: &ProtocolKind,
) -> String {
    if backend == frontend {
        return backend_type.to_owned();
    }
    let canonical = parse_backend_type(backend_type, backend);
    canonical.to_protocol_type(frontend).to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_mysql_int_to_postgresql() {
        assert_eq!(
            map_column_type("long", &ProtocolKind::MySql, &ProtocolKind::PostgreSql),
            "int4"
        );
        assert_eq!(
            map_column_type("longlong", &ProtocolKind::MySql, &ProtocolKind::PostgreSql),
            "int8"
        );
    }

    #[test]
    fn maps_postgresql_types_to_mysql() {
        assert_eq!(
            map_column_type("int4", &ProtocolKind::PostgreSql, &ProtocolKind::MySql),
            "long"
        );
        assert_eq!(
            map_column_type("bool", &ProtocolKind::PostgreSql, &ProtocolKind::MySql),
            "tiny"
        );
        assert_eq!(
            map_column_type("bytea", &ProtocolKind::PostgreSql, &ProtocolKind::MySql),
            "blob"
        );
        assert_eq!(
            map_column_type("timestamptz", &ProtocolKind::PostgreSql, &ProtocolKind::MySql),
            "timestamp"
        );
    }

    #[test]
    fn same_protocol_passthrough() {
        assert_eq!(
            map_column_type("int4", &ProtocolKind::PostgreSql, &ProtocolKind::PostgreSql),
            "int4"
        );
    }
}

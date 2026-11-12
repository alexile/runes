//! Shared test support: validation against the official SARIF 2.1.0 JSON
//! schema.
//!
//! `schema/sarif-schema-2.1.0.json` is the OASIS schema, vendored unchanged
//! from <https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json>
//! (identical to `sarif-2.1/schema/sarif-schema-2.1.0.json` in
//! <https://github.com/oasis-tcs/sarif-spec>). It is distributed under the
//! OASIS IPR Policy, is test data only, and is excluded from the published
//! crate.

#![allow(
    dead_code,
    clippy::expect_used,
    reason = "shared by several test binaries; a broken schema should fail loudly"
)]

use serde_json::Value;

const SCHEMA: &str = include_str!("../schema/sarif-schema-2.1.0.json");
const SCHEMA_URL: &str =
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json";

/// The compiled SARIF 2.1.0 schema.
pub struct Validator {
    schemas: boon::Schemas,
    index: boon::SchemaIndex,
}

impl Validator {
    pub fn new() -> Self {
        let schema: Value = serde_json::from_str(SCHEMA).expect("vendored schema is JSON");
        let mut schemas = boon::Schemas::new();
        let mut compiler = boon::Compiler::new();
        // Draft-04 asserts `format` (uri, date-time, ...) by default.
        compiler
            .add_resource(SCHEMA_URL, schema)
            .expect("add schema");
        let index = compiler
            .compile(SCHEMA_URL, &mut schemas)
            .expect("compile schema");
        Self { schemas, index }
    }

    /// `Err` with every violation when `instance` does not conform.
    pub fn validate(&self, instance: &Value) -> Result<(), String> {
        self.schemas
            .validate(instance, self.index)
            .map_err(|error| format!("{error:#}"))
    }
}

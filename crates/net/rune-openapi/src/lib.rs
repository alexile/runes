//! `OpenAPI` 3.0 / 3.1 / 3.2 and Swagger 2.0 import into a normalized
//! endpoint model, with example requests and insertion points.
//!
//! [`parse`] reads a document (JSON, or YAML with the default `yaml`
//! feature) and returns an [`ApiSpec`]: one [`Endpoint`] per operation with
//!
//! - typed [`Parameter`]s for the path, query, headers and cookies, with
//!   their serialization [`ParameterStyle`];
//! - the [`RequestBody`] per media type, including Swagger 2.0 `body` and
//!   `formData` parameters, and the declared [`Response`]s;
//! - normalized [`Schema`]s: `$ref`s resolved, `allOf` merged, `oneOf` /
//!   `anyOf` kept as variants, 3.1 type arrays and numeric exclusive bounds
//!   folded in, recursion cut off;
//! - the [`SecurityRequirement`]s that apply;
//! - an example [`HttpRequest`] (from `rune-http-model`) filled with
//!   document examples or values synthesized from the schemas, and its
//!   [`InsertionPoint`]s: every parameter, form field, JSON pointer and XML
//!   element a scanner or fuzzer can mutate, each with its schema.
//!
//! The crate is sans-I/O. External `$ref`s are not fetched: they, and other
//! problems inside a valid document, become [`ApiSpec::warnings`].
//!
//! Specifications: [`OpenAPI` 3.1.1](https://spec.openapis.org/oas/v3.1.1),
//! [`OpenAPI` 3.0.4](https://spec.openapis.org/oas/v3.0.4) and
//! [Swagger 2.0](https://swagger.io/specification/v2/).
//!
//! # Features
//!
//! - `yaml` (default): YAML 1.2 input via the safe-Rust `yaml-rust2`
//!   parser, with depth and alias-expansion limits.
//! - `serde`: `Serialize`/`Deserialize` for the model (with
//!   `rune-http-model/serde`).
//! - `schemars`: `JsonSchema` for the model (implies `serde`).
//!
//! # Example
//!
//! ```
//! use rune_openapi::{InsertionLocation, Options, SchemaType, parse};
//!
//! let doc = br##"{
//!   "openapi": "3.0.3",
//!   "servers": [{"url": "https://shop.example.test/v1"}],
//!   "paths": {
//!     "/orders": {
//!       "post": {
//!         "operationId": "createOrder",
//!         "parameters": [{"name": "dryRun", "in": "query", "schema": {"type": "boolean"}}],
//!         "requestBody": {"required": true, "content": {"application/json": {
//!           "schema": {"$ref": "#/components/schemas/Order"}}}}
//!       }
//!     }
//!   },
//!   "components": {"schemas": {"Order": {
//!     "type": "object", "required": ["sku"],
//!     "properties": {
//!       "sku": {"type": "string", "example": "A-1"},
//!       "quantity": {"type": "integer", "minimum": 1}
//!     }
//!   }}}
//! }"##;
//!
//! let spec = parse(doc, &Options::default())?;
//! let order = spec.endpoint("createOrder").unwrap();
//! assert_eq!(order.request.method, "POST");
//! assert_eq!(order.request.url, "https://shop.example.test/v1/orders?dryRun=true");
//! let body: serde_json::Value = serde_json::from_slice(order.request.body.as_bytes())?;
//! assert_eq!(body, serde_json::json!({"quantity": 1, "sku": "A-1"}));
//!
//! let sku = order.insertion_point(InsertionLocation::JsonPointer, "/sku").unwrap();
//! assert!(sku.required);
//! assert_eq!(sku.schema_type(), SchemaType::String);
//! assert_eq!(order.insertion_points.len(), 3); // dryRun, /quantity, /sku
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod document;
mod error;
mod import;
mod model;
mod render;
mod schema;
#[cfg(feature = "yaml")]
mod yaml;

pub use error::OpenApiError;
pub use import::{from_value, parse};
pub use model::{
    ApiKeyLocation, ApiSpec, Endpoint, InsertionLocation, InsertionPoint, MediaType, Options,
    Parameter, ParameterLocation, ParameterStyle, RenderedRequest, RequestBody, Response,
    SecurityRequirement, SecurityScheme, SecuritySchemeRef, SpecVersion,
};
pub use render::MULTIPART_BOUNDARY;
pub use schema::{ExampleStrategy, Property, Schema, SchemaType};

/// The request type endpoints are rendered to.
pub use rune_http_model::HttpRequest;
/// JSON values used for examples and enum values.
pub use serde_json::Value;
/// The URL type of [`Options::base_url`].
pub use url::Url;

#[cfg(all(doctest, feature = "yaml"))]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

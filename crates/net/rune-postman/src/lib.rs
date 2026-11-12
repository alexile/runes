//! Postman collection import over [`rune_http_model`].
//!
//! Reads [Postman Collection Format v2.0 and v2.1] exports, with their
//! environments and globals, into ready-to-send
//! [`HttpRequest`](rune_http_model::HttpRequest)s. It works on bytes only:
//! callers bring their own files.
//!
//! - **Folders**: items are walked depth first; each
//!   [`CollectionRequest`] keeps its folder path, name, id and description.
//! - **Variables**: `{{name}}` placeholders resolve in the URL, headers,
//!   bodies and auth parameters, through Postman's scopes from narrowest
//!   to widest: [`ReadOptions::variables`], values set by pre-request
//!   scripts with `pm.variables.set`, the [environment](Environment),
//!   collection (and folder) variables, then [globals](ReadOptions::globals).
//!   Values may refer to other variables; cycles and runaway expansion are
//!   cut off. URL path variables (`/users/:id`) are filled in. Undefined
//!   names stay as `{{name}}` and are listed in
//!   [`CollectionRequest::unresolved`].
//! - **Bodies**: `raw` (with a `Content-Type` from its language),
//!   `urlencoded`, `formdata` (multipart, with [`MULTIPART_BOUNDARY`]) and
//!   `graphql`. File contents are not part of an export: file parts are
//!   left empty, with a [`Warning`].
//! - **Auth helpers**, inherited from folders and the collection unless an
//!   item overrides them: `bearer`, `basic`, `apikey` (header or query) and
//!   `oauth2` with an exported access token. Headers set in the collection
//!   win over generated ones. Helpers that need a live exchange or a
//!   signature (`digest`, `oauth1`, `awsv4`, `hawk`, `ntlm`, …) are
//!   reported, not applied.
//! - **Scripts are data**: pre-request scripts are never run. Their source
//!   is kept in [`CollectionRequest::pre_request_scripts`], and literal
//!   assignments such as `pm.environment.set("token", "abc")` are applied
//!   to the scope they target.
//! - **Tolerant**: a byte-order mark, the API's `{"collection": …}`
//!   wrapper, `null` fields, numbers where text belongs and v2.0 shapes
//!   (auth objects, header blocks) are accepted. An item with a field of
//!   the wrong shape is skipped with a [`Warning`]; the rest still reads.
//!
//! # Example
//!
//! ```
//! use rune_postman::{Environment, ReadOptions};
//!
//! let collection = br#"{
//!   "info": {"name": "Shop", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
//!   "auth": {"type": "bearer", "bearer": [{"key": "token", "value": "{{token}}"}]},
//!   "variable": [{"key": "baseUrl", "value": "https://shop.test"}],
//!   "item": [{
//!     "name": "Orders",
//!     "item": [{
//!       "name": "Get order",
//!       "request": {
//!         "method": "get",
//!         "header": [{"key": "Accept", "value": "application/json"}],
//!         "url": {"raw": "{{baseUrl}}/orders/:id", "variable": [{"key": "id", "value": "42"}]}
//!       }
//!     }]
//!   }]
//! }"#;
//! let environment = Environment::new("dev").with_value("token", "t0k3n");
//!
//! let imported = rune_postman::read(collection, &ReadOptions::default().with_environment(environment))?;
//! let order = &imported.requests[0];
//! assert_eq!(order.path(), "Orders/Get order");
//! assert_eq!(order.request.method, "GET");
//! assert_eq!(order.request.url, "https://shop.test/orders/42");
//! assert_eq!(order.request.header("Authorization"), Some("Bearer t0k3n"));
//! assert!(imported.warnings.is_empty());
//! # Ok::<(), rune_postman::PostmanError>(())
//! ```
//!
//! [Postman Collection Format v2.0 and v2.1]: https://schema.postman.com/

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod environment;
mod error;
mod json;
mod read;
mod script;
mod vars;

use std::collections::BTreeMap;

pub use environment::{Environment, Variable, parse_environment};
pub use error::PostmanError;
pub use read::{Collection, CollectionRequest, MULTIPART_BOUNDARY, ReadOptions, Warning, read};
pub use vars::Resolved;

/// Resolves `{{name}}` placeholders in `text` from one set of variables.
///
/// Resolution works as for requests: recursively, with cycles and
/// undefined names left in place and listed, and growth capped at
/// `max_len` bytes (or the length of `text`, if longer).
///
/// ```
/// use std::collections::BTreeMap;
///
/// let variables = BTreeMap::from([
///     ("host".to_owned(), "h.test".to_owned()),
///     ("url".to_owned(), "https://{{host}}".to_owned()),
/// ]);
/// let resolved = rune_postman::resolve("{{url}}/{{path}}", &variables, 1024);
/// assert_eq!(resolved.text, "https://h.test/{{path}}");
/// assert_eq!(resolved.unresolved, ["path"]);
/// ```
#[must_use]
pub fn resolve(text: &str, variables: &BTreeMap<String, String>, max_len: usize) -> Resolved {
    vars::resolve_with(text, variables, max_len)
}

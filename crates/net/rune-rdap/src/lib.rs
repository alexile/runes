//! RDAP, the structured successor of WHOIS: registration data for domains,
//! IP networks, autonomous systems, nameservers and entities.
//!
//! The core is sans-I/O:
//!
//! - [`Query`] parses what to look up and renders its RDAP path
//!   ([RFC 9082](https://www.rfc-editor.org/rfc/rfc9082)).
//! - [`bootstrap`] parses the IANA bootstrap registries and routes a query
//!   to the server that holds it
//!   ([RFC 9224](https://www.rfc-editor.org/rfc/rfc9224), and
//!   [RFC 8521](https://www.rfc-editor.org/rfc/rfc8521) object tags for
//!   entity handles).
//! - [`response`] classifies HTTP responses (object, redirect, not found,
//!   rate limited, error) and [`parse_object`] turns JSON into the typed
//!   models of [`model`] ([RFC 9083](https://www.rfc-editor.org/rfc/rfc9083)):
//!   registrar, dates, nameservers, entities with their jCard contacts,
//!   status.
//! - [`cache::TtlCache`] and [`ratelimit::RateLimiter`] are clock-driven
//!   building blocks for callers that bring their own I/O.
//!
//! With the `client` feature, [`client::Client`] ties these together over
//! any HTTP transport ([`client::Fetcher`]); the `reqwest` feature supplies
//! one. It caches bootstrap files and objects, follows redirects and
//! spaces requests per host.
//!
//! # Example
//!
//! Route a query with a bootstrap file and read a server's answer, all in
//! memory:
//!
//! ```
//! use rune_rdap::bootstrap::{Bootstrap, Registry, RegistryKind};
//! use rune_rdap::model::{Role, Status};
//! use rune_rdap::response::{Outcome, Response, interpret};
//! use rune_rdap::Query;
//!
//! let dns = br#"{"version":"1.0","publication":"2026-10-28T22:00:04Z","services":[
//!     [["com","net"],["https://rdap.verisign.com/com/v1/"]]]}"#;
//! let bootstrap = Bootstrap::new().with(Registry::parse(RegistryKind::Dns, dns)?);
//!
//! let query = Query::parse("EXAMPLE.com")?;
//! let url = &bootstrap.urls(&query)?[0];
//! assert_eq!(url, "https://rdap.verisign.com/com/v1/domain/example.com");
//!
//! // …GET `url` with `Accept: application/rdap+json`, then:
//! let body = r#"{
//!   "objectClassName": "domain", "ldhName": "EXAMPLE.COM",
//!   "status": ["client transfer prohibited"],
//!   "entities": [{"objectClassName": "entity", "roles": ["registrar"],
//!     "publicIds": [{"type": "IANA Registrar ID", "identifier": "376"}],
//!     "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
//!                              ["fn", {}, "text", "RESERVED-Internet Assigned Numbers Authority"]]]}],
//!   "events": [{"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
//!              {"eventAction": "expiration", "eventDate": "2027-08-13T04:00:00Z"}],
//!   "nameservers": [{"objectClassName": "nameserver", "ldhName": "A.IANA-SERVERS.NET"}]
//! }"#;
//! let Outcome::Object(object) = interpret(&Response::new(200, body))? else {
//!     unreachable!("a 200 with an object")
//! };
//! let domain = object.as_domain().unwrap();
//! assert_eq!(domain.registrar_name(), Some("RESERVED-Internet Assigned Numbers Authority"));
//! assert_eq!(domain.registrar_iana_id(), Some("376"));
//! assert_eq!(domain.registration(), Some("1995-08-14T04:00:00Z"));
//! assert_eq!(domain.expiration(), Some("2027-08-13T04:00:00Z"));
//! assert_eq!(domain.nameserver_names().collect::<Vec<_>>(), ["A.IANA-SERVERS.NET"]);
//! assert!(domain.has_status(&Status::ClientTransferProhibited));
//! assert!(domain.entity_with_role(&Role::Registrant).is_none());
//! # Ok::<(), rune_rdap::Error>(())
//! ```
//!
//! With the `reqwest` feature, the client does the fetching:
//!
//! ```no_run
//! # #[cfg(feature = "reqwest")]
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! use rune_rdap::client::{Client, Options, ReqwestFetcher};
//!
//! let client = Client::new(ReqwestFetcher::new()?, Options::default());
//! let found = client.lookup_str("AS15169").await?;
//! println!("{:?}", found.object.as_autnum().and_then(|a| a.name.as_deref()));
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod bootstrap;
pub mod cache;
#[cfg(feature = "client")]
pub mod client;
mod error;
pub mod model;
mod query;
pub mod ratelimit;
pub mod response;
mod vcard;

pub use error::Error;
pub use model::Object;
pub use query::Query;
pub use response::parse_object;
pub use vcard::Contact;

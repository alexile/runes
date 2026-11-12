//! Client-side HTTP authentication helpers, sans-I/O.
//!
//! - [`Challenge`] parses `WWW-Authenticate` / `Proxy-Authenticate`
//!   challenge lists and `Authorization` credentials ([RFC 9110 §11]).
//! - [`BasicCredentials`] builds, parses and verifies Basic credentials
//!   ([RFC 7617]); [`constant_time_eq`] compares secrets without timing
//!   leaks. [`bearer`] / [`parse_bearer`] handle Bearer tokens
//!   ([RFC 6750]).
//! - [`DigestChallenge`] / [`DigestResponse`] implement Digest
//!   ([RFC 7616]): MD5, SHA-256 and SHA-512/256, their `-sess` variants,
//!   `qop=auth` / `auth-int`, `userhash`, and the RFC 2069 form; both the
//!   client response and server-side verification.
//! - [`NtlmMessage`] encodes and decodes the NTLM NEGOTIATE / CHALLENGE /
//!   AUTHENTICATE messages and their `NTLM` / `Negotiate` header framing
//!   ([MS-NLMP], [MS-NTHT]); [`authenticate`] answers a challenge with
//!   `NTLMv2`.
//! - The [`rune_http_model`] glue reads challenges from an
//!   [`HttpResponse`](rune_http_model::HttpResponse) and sets
//!   `Authorization` on an [`HttpRequest`](rune_http_model::HttpRequest).
//!
//! Randomness (client nonces, NTLM client challenges) and time are inputs:
//! the caller supplies them.
//!
//! # Example
//!
//! ```
//! use rune_http_auth::{
//!     BasicCredentials, DigestChallenge, DigestRequest, response_challenges,
//! };
//! use rune_http_model::HttpResponse;
//!
//! let response = HttpResponse::new(401).with_header(
//!     "WWW-Authenticate",
//!     "Digest realm=\"testrealm@host.com\", qop=\"auth,auth-int\", \
//!      nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", \
//!      opaque=\"5ccc069c403ebaf9f0171e9517f40e41\", Basic realm=\"x\"",
//! );
//! let challenges = response_challenges(&response).unwrap();
//! assert_eq!(challenges.len(), 2);
//!
//! // RFC 2617 §3.5.
//! let digest = DigestChallenge::from_challenge(&challenges[0]).unwrap();
//! let request = DigestRequest::new("GET", "/dir/index.html").with_cnonce("0a4f113b");
//! let answer = digest.respond("Mufasa", "Circle Of Life", &request);
//! assert_eq!(answer.response, "6629fae49393a05397450978507c4ef1");
//!
//! let basic = BasicCredentials::new("Aladdin", "open sesame").unwrap();
//! assert_eq!(basic.to_string(), "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
//! ```
//!
//! [RFC 9110 §11]: https://www.rfc-editor.org/rfc/rfc9110#section-11
//! [RFC 7617]: https://www.rfc-editor.org/rfc/rfc7617
//! [RFC 6750]: https://www.rfc-editor.org/rfc/rfc6750
//! [RFC 7616]: https://www.rfc-editor.org/rfc/rfc7616
//! [MS-NLMP]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/
//! [MS-NTHT]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ntht/

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod basic;
mod challenge;
mod digest;
mod error;
mod http;
mod ntlm;

pub use basic::{BasicCredentials, bearer, constant_time_eq, parse_bearer};
pub use challenge::Challenge;
pub use digest::{DigestAlgorithm, DigestChallenge, DigestRequest, DigestResponse, Qop};
pub use error::AuthError;
pub use http::{
    digest_request, digest_uri, request_credentials, response_challenges, set_authorization,
};
pub use ntlm::{
    AuthenticateMessage, AvPair, ChallengeMessage, NegotiateFlags, NegotiateMessage,
    NtlmCredentials, NtlmMessage, NtlmScheme, Ntlmv2Response, Version, authenticate, nt_hash,
    ntlmv2_response, ntowf_v2,
};

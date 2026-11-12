# rune-http-auth

> Client-side HTTP authentication: Basic, Bearer, Digest (RFC 7616) and NTLM/Negotiate message framing over rune-http-model

[![crates.io](https://img.shields.io/crates/v/rune-http-auth)](https://crates.io/crates/rune-http-auth)
[![docs.rs](https://img.shields.io/docsrs/rune-http-auth)](https://docs.rs/rune-http-auth)
[![license](https://img.shields.io/crates/l/rune-http-auth)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

Sans-I/O helpers for the authentication schemes a workbench or session
engine meets:

- **Challenges**: `Challenge::parse_list` for `WWW-Authenticate` /
  `Proxy-Authenticate` lists, `Challenge::parse` for `Authorization`
  ([RFC 9110 §11](https://www.rfc-editor.org/rfc/rfc9110#section-11)).
- **Basic** ([RFC 7617](https://www.rfc-editor.org/rfc/rfc7617)): build,
  parse and verify, with `constant_time_eq` (SHA-256 then constant-time
  compare, so lengths do not leak either).
- **Bearer** ([RFC 6750](https://www.rfc-editor.org/rfc/rfc6750)).
- **Digest** ([RFC 7616](https://www.rfc-editor.org/rfc/rfc7616)): MD5,
  SHA-256, SHA-512/256 and `-sess`; `qop=auth` / `auth-int`; `userhash`;
  `username*`; RFC 2069 legacy form. Client responses and server-side
  verification.
- **NTLM / Negotiate** ([MS-NLMP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/)):
  NEGOTIATE, CHALLENGE and AUTHENTICATE messages (encode, decode, header
  framing, `AV_PAIR`s) and NTLMv2 responses (`authenticate`).

Client nonces, NTLM client challenges and timestamps are inputs: bring
your own randomness and clock. Not covered: SPNEGO/Kerberos tokens, NTLM
MIC and session security.

## Installation

```toml
[dependencies]
rune-http-auth = "0.1"
```

## Usage

```rust
use rune_http_auth::{
    ChallengeMessage, DigestChallenge, DigestRequest, NegotiateFlags, NegotiateMessage,
    NtlmCredentials, NtlmMessage, NtlmScheme, authenticate,
};

// Digest (RFC 7616 §3.9.1).
let challenge = DigestChallenge::parse(
    "Digest realm=\"http-auth@example.org\", qop=\"auth, auth-int\", algorithm=MD5, \
     nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\", \
     opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\"",
)
.unwrap();
let request = DigestRequest::new("GET", "/dir/index.html")
    .with_cnonce("f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ");
let answer = challenge.respond("Mufasa", "Circle of Life", &request);
assert_eq!(answer.response, "8ca523f5e9506fed4657c9700eebdbec");
let authorization = answer.to_string();

// NTLM: type 1 out, type 2 in, type 3 out.
let type1 = NtlmMessage::Negotiate(NegotiateMessage::new()).to_header(NtlmScheme::Ntlm).unwrap();
let server = NtlmMessage::Challenge(ChallengeMessage::new(NegotiateFlags::CLIENT_DEFAULT, [1; 8]))
    .to_header(NtlmScheme::Ntlm)
    .unwrap();
let (scheme, NtlmMessage::Challenge(type2)) = NtlmMessage::from_header(&server).unwrap() else {
    unreachable!()
};
let creds = NtlmCredentials::new("CORP", "alice", "s3cret");
let type3 = NtlmMessage::Authenticate(authenticate(&type2, &creds, "WS01", [2; 8], 0))
    .to_header(scheme)
    .unwrap();
```

## License

MIT

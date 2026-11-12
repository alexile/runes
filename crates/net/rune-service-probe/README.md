# rune-service-probe

> Read-only service probing framework: a sans-I/O ServiceProbe trait, ServiceInfo model and a bounded tokio runner

[![crates.io](https://img.shields.io/crates/v/rune-service-probe)](https://crates.io/crates/rune-service-probe)
[![docs.rs](https://img.shields.io/docsrs/rune-service-probe)](https://docs.rs/rune-service-probe)
[![license](https://img.shields.io/crates/l/rune-service-probe)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

The shared core for read-only protocol probes (SSH, SQL and NoSQL
databases, SMTP/FTP, LDAP, SMB/RDP, SNMP/NTP). Each protocol lives in its
own `rune-probe-*` crate and implements one trait; this crate runs them.

- **`ServiceProbe`**: an object-safe trait with an `id`, a transport (TCP or
  UDP), a safety class (`ReadOnly` or `Intrusive`), well-known ports, and a
  `session` factory.
- **`ProbeSession`**: a sans-I/O state machine. It returns `Send(bytes)`,
  `Receive` or `Done`, is fed whatever the server sends, and finishes with a
  `ServiceInfo` or an `Error` (`Unrecognized`, `NoResponse`).
- **`ServiceInfo`**: product, version, banner, capabilities, TLS support
  (`NotOffered`, `Optional`, `Required`, `Implicit`), authentication
  requirement, protocol details, and [`rune-finding`](../../secops/rune-finding)
  findings located at the endpoint.
- **`Driver`** enforces a read budget, a step budget and the safety policy
  (intrusive probes are refused unless allowed), without doing I/O.
  **`simulate`** runs a probe against scripted replies, in memory.
- **`Runner`** (feature `tokio`): connects over TCP or UDP with connect, I/O
  and total timeouts and a concurrency bound, or runs over a stream the
  caller opened (TLS for SMTPS or LDAPS). It applies no scope policy:
  check targets first and pin the address with `Target::with_addr`.
- **`banner`**: `printable` for untrusted bytes, `split_line`, and a generic
  `BannerProbe`. **`ProbeSet`** looks probes up by id or port.

## Installation

```toml
[dependencies]
rune-service-probe = { version = "0.1", features = ["tokio"] }
```

| Feature | Enables                                                           |
| ------- | ----------------------------------------------------------------- |
| `tokio` | `Runner`: async TCP/UDP probing with timeouts and concurrency bound |
| `serde` | Serialize and deserialize the model types and their findings      |

## Usage

### Writing a probe

```rust
use rune_service_probe::{
    Action, AuthRequirement, End, Error, Options, ProbeSession, ServiceInfo, ServiceProbe,
    Target, simulate,
};

/// Redis `PING`: a `+PONG` without `AUTH` means the server is open.
struct RedisPing;

impl ServiceProbe for RedisPing {
    fn id(&self) -> &str { "redis" }
    fn default_ports(&self) -> &[u16] { &[6379] }
    fn session(&self, _target: &Target) -> Box<dyn ProbeSession> {
        Box::new(Session(Vec::new()))
    }
}

struct Session(Vec<u8>);

impl ProbeSession for Session {
    fn start(&mut self) -> Action { Action::Send(b"PING\r\n".to_vec()) }
    fn on_data(&mut self, data: &[u8]) -> Action {
        self.0.extend_from_slice(data);
        if self.0.ends_with(b"\r\n") { Action::Done } else { Action::Receive }
    }
    fn finish(&mut self, _end: End) -> Result<ServiceInfo, Error> {
        let auth = match self.0.as_slice() {
            [] => return Err(Error::no_response("redis")),
            b if b.starts_with(b"+PONG") => AuthRequirement::NotRequired,
            b if b.starts_with(b"-NOAUTH") => AuthRequirement::Required,
            _ => return Err(Error::unrecognized("redis", "not a RESP reply")),
        };
        Ok(ServiceInfo::new("redis").with_auth(auth))
    }
}

let target = Target::new("cache", 6379);
let sim = simulate(&RedisPing, &target, &[b"+PONG\r\n"], &Options::default()).unwrap();
assert_eq!(sim.sent, [b"PING\r\n".to_vec()]);
assert_eq!(sim.result.unwrap().auth, AuthRequirement::NotRequired);
```

### Running probes

```rust
use rune_service_probe::banner::BannerProbe;
use rune_service_probe::{Options, Runner, ServiceProbe, Target};

async fn demo() {
    let runner = Runner::new(Options::default().with_max_concurrency(16));
    let probe = BannerProbe::new();
    let targets = [Target::new("192.0.2.10", 22), Target::new("192.0.2.10", 25)];
    for result in runner
        .probe_all(targets.iter().map(|t| (&probe as &dyn ServiceProbe, t)))
        .await
    {
        match result {
            Ok(info) => println!("{:?}", info.banner),
            Err(err) => eprintln!("{err}"),
        }
    }
}
```

## Conventions for probe crates

- `id` is lowercase (`ssh`, `mysql`); finding check ids are
  `<id>.<issue>` (`redis.unauthenticated`); `details` keys are `<id>.<name>`.
  Build findings with `Target::finding` so they carry the endpoint.
- Probes are `ReadOnly`: no writes, no credentials, no login. Anything that
  could change state is a separate probe declared `Intrusive`.
- Return partial `ServiceInfo` when a session ends early; test sessions
  with `simulate` and fuzz them the same way.

## License

MIT

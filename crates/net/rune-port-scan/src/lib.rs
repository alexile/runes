//! Async TCP connect scanning with port-list parsing, rate limiting and
//! service and OS hints, for authorised network assessment.
//!
//! The crate is layered:
//!
//! - **Port lists** — [`PortSet`] parses `22,80,443,8000-8100,top-20`
//!   (ranges, open-ended ranges, `all`, and the first `N` of
//!   [`TOP_PORTS`]) and formats back to the canonical list.
//! - **Hints** — [`port_service`], [`banner_hint`], [`hint`] and
//!   [`os_hint`] turn a port number and a server-first banner into a
//!   [`ServiceHint`] (service, product, version) and a coarse [`OsHint`].
//!   They are sans-I/O, bounded and safe on hostile banners.
//! - **Planning** — [`Options`] (with nmap-like [`Timing`] presets), the
//!   sans-I/O rate [`Pacer`], and the [`Report`] model.
//! - **Scanning** — `Scanner` (feature `tokio`) runs full TCP connects
//!   with a semaphore-bounded worker pool, an even attempt rate and
//!   timeouts, and optionally reads banners. It never writes to a port.
//!
//! The scanner applies no scope policy and resolves no names: it connects
//! to the addresses it is handed. Scan only systems you are authorised to
//! test; [`Options::max_targets`] guards against accidentally large sweeps.
//!
//! # Example
//!
//! Planning and hinting, without touching the network:
//!
//! ```
//! use std::net::SocketAddr;
//! use std::time::Duration;
//! use rune_port_scan::{Options, PortResult, PortSet, PortState, Report};
//!
//! let ports: PortSet = "22,80,8000-8002,top-5".parse()?;
//! assert_eq!(ports.to_string(), "22,80,8000-8002,23,443,21");
//! let options = Options::default().with_rate(Some(100)).with_max_targets(1_000);
//! assert!(options.check_size(256, ports.len()).is_err()); // 2048 pairs
//!
//! // What a scan reports for an SSH banner:
//! let addr: SocketAddr = "192.0.2.7:2222".parse().unwrap();
//! let mut result = PortResult::new(addr, PortState::Open, Duration::from_millis(3));
//! result.banner = Some(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n".to_vec());
//! let report = Report::new(vec![result.with_hints()], Duration::from_millis(5));
//! let ssh = report.results[0].service.as_ref().unwrap();
//! assert_eq!((ssh.service.as_str(), ssh.version.as_deref()), ("ssh", Some("9.6p1")));
//! assert_eq!(report.os_hint(addr.ip()), Some(rune_port_scan::OsHint::Linux));
//! # Ok::<(), rune_port_scan::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod error;
mod hint;
mod plan;
mod ports;
#[cfg(feature = "tokio")]
mod scan;

pub use error::{Error, Result};
pub use hint::{
    HintSource, MAX_HINT_BANNER, OsHint, ServiceHint, banner_hint, hint, os_hint, port_service,
};
pub use plan::{Options, Pacer, PortResult, PortState, Report, Stats, Timing};
pub use ports::{PortSet, TOP_PORTS};
#[cfg(feature = "tokio")]
pub use scan::Scanner;

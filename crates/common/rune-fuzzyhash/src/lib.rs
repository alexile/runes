//! TLSH and ssdeep fuzzy hashes for finding near-identical files and
//! payloads: favicon variants, JS bundle versions, copied code, malware
//! families.
//!
//! | Algorithm | Digest | Similarity | Recommendation |
//! | --- | --- | --- | --- |
//! | [TLSH](tlsh) (preferred) | `T1` + 70 hex | [`Tlsh::distance`]: 0 = identical, grows unbounded | ≤ [`tlsh::RECOMMENDED_MAX_DISTANCE`] (50); ≤ [`tlsh::STRICT_MAX_DISTANCE`] (30) for few false positives |
//! | [ssdeep](ssdeep) (CTPH) | `blocksize:d1:d2` | [`Ssdeep::compare`]: 0–100, 100 = identical | ≥ [`ssdeep::RECOMMENDED_MIN_SCORE`] (50); > 0 means some shared content |
//!
//! Prefer TLSH: its distance is a metric-like score that holds up under
//! reordering and spread-out edits, and any two digests are comparable.
//! ssdeep is better at spotting one file *embedded* in another, but only
//! compares digests whose block sizes are within a factor of two, and needs
//! more than a few hundred bytes to say anything. TLSH needs at least 50
//! bytes with some variety.
//!
//! Both produce output identical to the reference implementations (TLSH
//! 4.x `T1` digests, ssdeep 2.14), so digests interoperate with existing
//! databases such as `VirusTotal` or `MalwareBazaar`. Sans-I/O: bytes in,
//! digest out.
//!
//! # Example
//!
//! ```
//! use rune_fuzzyhash::{Ssdeep, Tlsh};
//!
//! // Two builds of a script that differ in one line.
//! let v1: String = (0..300).map(|i| format!("function f{i}(x) {{ return x * {i}; }}\n")).collect();
//! let v2 = v1.replace("function f150(x) { return x * 150; }", "function f150(x) { return x - 1; }");
//!
//! let (a, b) = (Tlsh::hash(v1.as_bytes())?, Tlsh::hash(v2.as_bytes())?);
//! assert!(a.distance(&b) <= rune_fuzzyhash::tlsh::STRICT_MAX_DISTANCE);
//! println!("{a}");
//!
//! let (a, b) = (Ssdeep::hash(v1.as_bytes())?, Ssdeep::hash(v2.as_bytes())?);
//! assert!(a.compare(&b) >= rune_fuzzyhash::ssdeep::RECOMMENDED_MIN_SCORE);
//!
//! // Digests round-trip through their string form.
//! assert_eq!(a.to_string().parse::<Ssdeep>()?, a);
//! # Ok::<(), rune_fuzzyhash::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod error;
pub mod ssdeep;
pub mod tlsh;

pub use error::Error;
pub use ssdeep::Ssdeep;
pub use tlsh::{Tlsh, TlshBuilder};

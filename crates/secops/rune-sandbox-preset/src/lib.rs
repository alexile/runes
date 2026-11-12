//! Reusable sandbox presets over `rune-namespaces`, `rune-seccomp`,
//! `rune-landlock` and `rune-egress-proxy`: sane defaults for common kinds
//! of program, without `rune-secops-warden`'s TOML policy engine.
//!
//! A [`Preset`] is one declarative description of a sandbox — host paths
//! it may see ([`Grant`]s), paths it may not ([`Preset::masks`]), its
//! environment, network access and system call filter — that compiles to
//! each mechanism from the same data, so the layers cannot disagree:
//!
//! | Mechanism                   | From                          |
//! | --------------------------- | ----------------------------- |
//! | namespaces, mounts, env     | [`Preset::namespace_options`] |
//! | seccomp-bpf                 | [`Preset::seccomp_program`]   |
//! | Landlock (defense in depth) | [`Preset::landlock_options`], [`Preset::landlock_wrapper`] |
//! | domain-allowlisted egress   | [`Network::Proxied`]          |
//!
//! Two presets are ready-made:
//!
//! - [`dev_tool`]: an offline compiler, build system or test runner on one
//!   project. System directories read-only, the project read-write, no
//!   network, nothing of the home directory.
//! - [`network_tool`]: a downloader or API client. As `dev_tool`, plus
//!   DNS and TLS configuration and the network, either the host's or only
//!   an egress proxy's socket.
//!
//! Both pin `$PATH` to system directories ([`SAFE_PATH`]) and `$HOME` to a
//! path that exists in the sandbox, pass through only harmless variables
//! ([`PASSTHROUGH_VARS`]), and deny the dangerous system calls
//! ([`default_seccomp`]). The path lists they are built from
//! ([`DNS_FILES`], [`TLS_PATHS`], ...) come from tracing real programs in
//! `rune-secops-warden`, which builds its `claude_code` preset from them
//! too.
//!
//! Everything but [`Preset::command`] and [`secret_masks`] is pure:
//! building and inspecting a preset touches nothing. **Running** one needs
//! Linux with `bwrap` and unprivileged user namespaces.
//!
//! # Example
//!
//! ```
//! use rune_sandbox_preset::{DevToolOptions, MaskKind, dev_tool};
//! use rune_namespaces::{Access, Exposure};
//!
//! let preset = dev_tool(
//!     &DevToolOptions::new("/home/me/project")
//!         .with_read_write("/home/me/.cargo/registry")
//!         .with_masks([("/home/me/project/.env".into(), MaskKind::File)]),
//! );
//! preset.validate()?;
//!
//! assert_eq!(preset.exposure("/home/me/project/.env"), Exposure::Masked);
//! assert!(!preset.is_visible("/home/me/.ssh/id_ed25519"));
//! assert!(matches!(
//!     preset.exposure("/home/me/project/Cargo.toml"),
//!     Exposure::Host { access: Access::ReadWrite, .. }
//! ));
//!
//! // Widen it like any value: a tool that needs one more path.
//! let preset = preset.with_read_only("/opt/sdk");
//! assert!(preset.validate().is_ok());
//! # Ok::<(), rune_sandbox_preset::Error>(())
//! ```
//!
//! Running a program in it, with egress limited to two hosts:
//!
//! ```no_run
//! use rune_egress_proxy::{Policy, Proxy};
//! use rune_sandbox_preset::{Egress, Network, NetworkToolOptions, network_tool};
//! use std::os::unix::net::UnixListener;
//!
//! let socket = "/run/user/1000/egress.sock";
//! let policy = Policy::new().allow_hosts(["*.crates.io", "static.crates.io"])?;
//! let listener = UnixListener::bind(socket)?;
//! let proxy = Proxy::new(policy.clone());
//! std::thread::spawn(move || proxy.serve_unix(&listener));
//!
//! let preset = network_tool(
//!     &NetworkToolOptions::default()
//!         .with_work_dir("/srv/downloads")
//!         .with_network(Network::Proxied(Egress::new(policy, socket))),
//! );
//! let status = preset.command("/usr/bin/my-fetcher", &["--sync"])?.status()?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod paths;
mod preset;
mod presets;

pub use paths::{
    DEFAULT_HOME, DNS_FILES, HOST_IDENTITY_FILES, PASSTHROUGH_VARS, PROXY_SOCKET, SAFE_PATH,
    SECRET_NAMES, TLS_PATHS, USER_DB_FILES, secret_masks,
};
pub use preset::{Egress, Grant, GrantAccess, Network, Preset, default_seccomp};
pub use presets::{DevToolOptions, NetworkToolOptions, dev_tool, network_tool};
pub use rune_namespaces::MaskKind;

/// Errors returned by this crate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The preset is malformed or inconsistent.
    #[error("invalid preset: {reason}")]
    Invalid {
        /// Why.
        reason: String,
    },
    /// `rune-namespaces` rejected the options or could not build the
    /// command.
    #[error(transparent)]
    Namespaces(rune_namespaces::Error),
    /// The seccomp filter could not be compiled.
    #[error(transparent)]
    Seccomp(rune_seccomp::Error),
}

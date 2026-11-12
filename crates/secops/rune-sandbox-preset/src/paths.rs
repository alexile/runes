//! Building blocks shared by the presets: the host files common kinds of
//! program need, found by tracing real programs rather than guessed.
//!
//! `rune-secops-warden`'s `claude_code` preset is built from the same
//! lists, so a fix found there (or here) reaches both.

use std::io;
use std::path::{Path, PathBuf};

use rune_namespaces::{MaskKind, Mount};

/// Files glibc's resolver reads to turn a host name into an address.
///
/// It reads all of them, not just `resolv.conf`: `nsswitch.conf` decides the
/// lookup order, `hosts` is consulted first, `host.conf` and `gai.conf`
/// tune the answer. Missing ones are skipped.
pub const DNS_FILES: &[&str] = &[
    "/etc/resolv.conf",
    "/etc/nsswitch.conf",
    "/etc/hosts",
    "/etc/host.conf",
    "/etc/gai.conf",
];

/// The system CA bundle, which TLS clients need to verify a server. Whole
/// directories: distributions spread the bundle, its hashed symlinks and
/// the certificates they point at across both.
pub const TLS_PATHS: &[&str] = &["/etc/ssl", "/usr/share/ca-certificates"];

/// Files that identify the host and its clock.
///
/// Many runtimes read them at startup (Node, Bun, Python's `platform`,
/// glibc's `localtime`). `machine-id` is a stable host identifier; leave this list out for a
/// program that has no reason to know which machine it runs on.
pub const HOST_IDENTITY_FILES: &[&str] = &["/etc/machine-id", "/etc/os-release", "/etc/localtime"];

/// The user and group databases, for `getpwuid` and friends (`git`, `ssh`,
/// `whoami`, Python's `getpass`). They hold names and ids, not passwords.
pub const USER_DB_FILES: &[&str] = &["/etc/passwd", "/etc/group"];

/// A fixed `$PATH` of standard system directories only.
///
/// Presets pin `$PATH` instead of passing the host's through: a developer
/// shell's `$PATH` routinely has writable, project-local directories
/// (`node_modules/.bin`, a virtualenv, direnv shims) ahead of `/usr/bin`,
/// and a sandboxed shell that can write there can shadow every later bare
/// command name with its own binary.
pub const SAFE_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Host variables the presets pass through: locale and terminal settings
/// and the user's name. None of them usually carries a secret. `PATH` and
/// `HOME` are deliberately absent; the presets pin them.
pub const PASSTHROUGH_VARS: &[&str] = &["LANG", "LC_*", "TERM", "TZ", "USER", "LOGNAME"];

/// `$HOME` when a preset is not given one: the sandbox's private `/tmp`,
/// which exists, is writable and is thrown away afterwards.
pub const DEFAULT_HOME: &str = "/tmp";

/// Where a [`Network::Proxied`](crate::Network::Proxied) preset makes the
/// egress proxy's Unix socket appear inside the sandbox.
pub const PROXY_SOCKET: &str = "/run/rune-egress-proxy.sock";

/// Names of files and directories that, inside a project directory,
/// commonly hold credentials: dotenv files, package-registry tokens,
/// `netrc` and stored git credentials. See [`secret_masks`].
pub const SECRET_NAMES: &[&str] = &[
    ".env",
    ".env.local",
    ".env.development",
    ".env.production",
    ".envrc",
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".git-credentials",
];

/// Masks for every [`SECRET_NAMES`] entry that exists directly under
/// `dir`, choosing file or directory masks from what is on disk.
///
/// This is the one function in the crate that touches the filesystem: a
/// mask over a path that does not exist would make `bwrap` create it in a
/// read-write bind, that is, on the host. Pass the result to
/// [`Preset::with_masks`](crate::Preset::with_masks).
///
/// # Errors
///
/// If an entry exists but its metadata cannot be read.
pub fn secret_masks(dir: impl AsRef<Path>) -> io::Result<Vec<(PathBuf, MaskKind)>> {
    let dir = dir.as_ref();
    let mut masks = Vec::new();
    for name in SECRET_NAMES {
        if let Some(Mount::Mask { dest, kind }) = Mount::mask(dir.join(name))? {
            masks.push((dest, kind));
        }
    }
    Ok(masks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_are_absolute() {
        for path in DNS_FILES
            .iter()
            .chain(TLS_PATHS)
            .chain(HOST_IDENTITY_FILES)
            .chain(USER_DB_FILES)
            .chain([&DEFAULT_HOME, &PROXY_SOCKET])
        {
            assert!(Path::new(path).is_absolute(), "{path}");
        }
    }

    #[test]
    fn safe_path_has_only_system_directories() {
        for dir in SAFE_PATH.split(':') {
            assert!(
                [
                    "/usr/local/sbin",
                    "/usr/local/bin",
                    "/usr/sbin",
                    "/usr/bin",
                    "/sbin",
                    "/bin"
                ]
                .contains(&dir),
                "{dir}"
            );
        }
    }

    #[test]
    fn passthrough_vars_never_include_path_or_home() {
        assert!(!PASSTHROUGH_VARS.contains(&"PATH"));
        assert!(!PASSTHROUGH_VARS.contains(&"HOME"));
        assert!(!PASSTHROUGH_VARS.contains(&"SHELL"));
    }

    #[test]
    fn secret_masks_finds_only_existing_entries() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".env"), "TOKEN=x").unwrap();
        std::fs::create_dir(dir.path().join(".envrc")).unwrap();
        let masks = secret_masks(dir.path()).unwrap();
        assert_eq!(
            masks,
            vec![
                (dir.path().join(".env"), MaskKind::File),
                (dir.path().join(".envrc"), MaskKind::Dir),
            ]
        );
    }
}

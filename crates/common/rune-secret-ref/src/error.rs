//! The crate's single error type.

use std::io;
use std::path::PathBuf;
use std::process::ExitStatus;
use std::time::Duration;

use crate::SecretRef;

/// Why a reference could not be parsed or resolved.
///
/// No message ever contains secret material: parse errors do not echo the
/// rejected text (it may be an inline secret), and resolution errors name
/// the reference, never the value it produced.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SecretError {
    /// The text is not a reference at all: it looks like an inline secret.
    #[error(
        "inline secret values are not allowed; reference the secret instead \
         (`env:VAR`, `file:/path` or `cmd:program args`)"
    )]
    Inline,
    /// The scheme is known but the location is malformed.
    #[error("malformed `{scheme}:` secret reference: {reason}")]
    Malformed {
        /// The reference scheme, such as `env`.
        scheme: &'static str,
        /// What is wrong with the location.
        reason: &'static str,
    },
    /// The referenced environment variable is unset or empty.
    #[error("environment variable `{0}` referenced by a secret is not set or is empty")]
    EnvUnset(String),
    /// The referenced file could not be read.
    #[error("cannot read secret file `{path}`: {source}")]
    FileRead {
        /// The file path, after joining with the base directory.
        path: PathBuf,
        /// The I/O error.
        #[source]
        source: io::Error,
    },
    /// The referenced path exists but is not a regular file.
    #[error("secret file `{path}` is not a regular file")]
    NotAFile {
        /// The path.
        path: PathBuf,
    },
    /// The referenced file is accessible by group or others (unix only).
    #[error(
        "refusing secret file `{path}`: it is accessible by group or others \
         (mode {mode:o}); restrict it with `chmod 600`"
    )]
    InsecurePermissions {
        /// The file path.
        path: PathBuf,
        /// The file's permission bits.
        mode: u32,
    },
    /// The secret is longer than [`ResolveOptions::max_len`].
    ///
    /// [`ResolveOptions::max_len`]: crate::ResolveOptions::max_len
    #[error("secret from `{reference}` is larger than {limit} bytes")]
    TooLarge {
        /// The reference that produced it.
        reference: SecretRef,
        /// The configured limit in bytes.
        limit: usize,
    },
    /// The secret is not valid UTF-8.
    #[error("secret from `{reference}` is not valid UTF-8")]
    NotUtf8 {
        /// The reference that produced it.
        reference: SecretRef,
    },
    /// The secret is empty (after stripping one trailing newline).
    #[error("secret from `{reference}` is empty")]
    Empty {
        /// The reference that produced it.
        reference: SecretRef,
    },
    /// A `cmd:` reference was resolved without
    /// [`ResolveOptions::allow_command`].
    ///
    /// [`ResolveOptions::allow_command`]: crate::ResolveOptions::allow_command
    #[error(
        "secret command `{program}` was not run: command references are disabled \
         (enable them with `ResolveOptions::with_allow_command(true)`)"
    )]
    CommandDisabled {
        /// The program the reference names.
        program: String,
    },
    /// The command could not be started or its output could not be read.
    #[error("cannot run secret command `{program}`: {source}")]
    CommandIo {
        /// The program.
        program: String,
        /// The I/O error.
        #[source]
        source: io::Error,
    },
    /// The command exited unsuccessfully.
    #[error("secret command `{program}` failed: {status}")]
    CommandFailed {
        /// The program.
        program: String,
        /// Its exit status.
        status: ExitStatus,
    },
    /// The command did not finish in time and was killed.
    #[error("secret command `{program}` did not finish within {timeout:?}")]
    CommandTimeout {
        /// The program.
        program: String,
        /// The configured timeout.
        timeout: Duration,
    },
    /// The scheme is recognised but this crate has no backend for it; a
    /// secret provider (such as `rune-secret-vault`) resolves it.
    #[error(
        "`{scheme}:` secret references need a secret provider; this crate resolves only `env:`, `file:` and `cmd:`"
    )]
    Unsupported {
        /// The reference scheme.
        scheme: &'static str,
    },
}

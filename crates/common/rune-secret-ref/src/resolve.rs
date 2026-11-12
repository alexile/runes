//! Turning a [`SecretRef`] into a [`SecretValue`].

use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::value::wipe;
use crate::{SecretError, SecretRef, SecretValue};

/// How [`SecretRef::resolve`] reads secrets.
///
/// The defaults are the safe ones: command references are refused, secret
/// files must not be readable by group or others, and secrets are capped
/// at 64 KiB.
///
/// ```
/// use std::time::Duration;
/// use rune_secret_ref::ResolveOptions;
///
/// let options = ResolveOptions::default()
///     .with_allow_command(true)
///     .with_command_timeout(Duration::from_secs(30))
///     .with_base_dir("/etc/myapp");
/// assert!(options.allow_command);
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ResolveOptions {
    /// Run `cmd:` references. Off by default: a command in a config file
    /// is code execution, so enable it only for config the user owns (not,
    /// say, a project file from a freshly cloned repository).
    pub allow_command: bool,
    /// How long a command may run before it is killed. Default 10 s.
    pub command_timeout: Duration,
    /// On unix, refuse `file:` secrets whose mode grants any access to
    /// group or others. Default `true`.
    pub check_file_permissions: bool,
    /// Directory that relative `file:` paths join, and the working
    /// directory of commands. Usually the directory of the config file
    /// that held the reference. Default `None` (the process's working
    /// directory).
    pub base_dir: Option<PathBuf>,
    /// Largest secret accepted, in bytes. Default 64 KiB.
    pub max_len: usize,
}

impl Default for ResolveOptions {
    fn default() -> Self {
        Self {
            allow_command: false,
            command_timeout: Duration::from_secs(10),
            check_file_permissions: true,
            base_dir: None,
            max_len: 64 * 1024,
        }
    }
}

impl ResolveOptions {
    /// Sets [`allow_command`](Self::allow_command).
    #[must_use]
    pub const fn with_allow_command(mut self, allow: bool) -> Self {
        self.allow_command = allow;
        self
    }

    /// Sets [`command_timeout`](Self::command_timeout).
    #[must_use]
    pub const fn with_command_timeout(mut self, timeout: Duration) -> Self {
        self.command_timeout = timeout;
        self
    }

    /// Sets [`check_file_permissions`](Self::check_file_permissions).
    #[must_use]
    pub const fn with_check_file_permissions(mut self, check: bool) -> Self {
        self.check_file_permissions = check;
        self
    }

    /// Sets [`base_dir`](Self::base_dir).
    #[must_use]
    pub fn with_base_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.base_dir = Some(dir.into());
        self
    }

    /// Sets [`max_len`](Self::max_len).
    #[must_use]
    pub const fn with_max_len(mut self, max_len: usize) -> Self {
        self.max_len = max_len;
        self
    }
}

impl SecretRef {
    /// Resolves the secret.
    ///
    /// Environment variables are looked up through `env`, so the library
    /// never reads the process environment on its own: pass
    /// `|name| std::env::var(name).ok()` for the real one, or a map in
    /// tests.
    ///
    /// - `env:` — the variable's value; unset or empty is an error.
    /// - `file:` — the file's contents with one trailing `\n` or `\r\n`
    ///   removed.
    /// - `cmd:` — the program's standard output, trimmed the same way.
    ///   The program runs without a shell, with standard input closed and
    ///   standard error inherited (so it can explain a failure), and is
    ///   killed after [`ResolveOptions::command_timeout`].
    ///
    /// # Errors
    ///
    /// A [`SecretError`] naming the reference, never the secret: the
    /// variable is unset, the file is unreadable or too open, the command
    /// is disabled, fails or times out, the secret is empty, too large or
    /// not UTF-8, or the scheme (`keychain:`, `vault:`) needs a secret
    /// provider.
    pub fn resolve(
        &self,
        options: &ResolveOptions,
        env: impl Fn(&str) -> Option<String>,
    ) -> Result<SecretValue, SecretError> {
        match self {
            Self::Env(name) => env(name)
                .filter(|value| !value.is_empty())
                .map(SecretValue::from)
                .ok_or_else(|| SecretError::EnvUnset(name.clone())),
            Self::File(path) => {
                let path = options
                    .base_dir
                    .as_ref()
                    .map_or_else(|| path.clone(), |base| base.join(path));
                let bytes = read_file(&path, options)?;
                self.finish(bytes, options)
            }
            Self::Command { program, args } => {
                if !options.allow_command {
                    return Err(SecretError::CommandDisabled {
                        program: program.clone(),
                    });
                }
                let bytes = run_command(program, args, options)?;
                self.finish(bytes, options)
            }
            Self::Keychain { .. } | Self::Vault(_) => Err(SecretError::Unsupported {
                scheme: self.scheme(),
            }),
        }
    }

    /// Checks size, strips one trailing newline, and validates UTF-8.
    fn finish(
        &self,
        mut bytes: Vec<u8>,
        options: &ResolveOptions,
    ) -> Result<SecretValue, SecretError> {
        if bytes.len() > options.max_len {
            wipe(&mut bytes);
            return Err(SecretError::TooLarge {
                reference: self.clone(),
                limit: options.max_len,
            });
        }
        if bytes.last() == Some(&b'\n') {
            bytes.pop();
            if bytes.last() == Some(&b'\r') {
                bytes.pop();
            }
        }
        if bytes.is_empty() {
            return Err(SecretError::Empty {
                reference: self.clone(),
            });
        }
        match String::from_utf8(bytes) {
            Ok(text) => Ok(SecretValue::from(text)),
            Err(error) => {
                wipe(&mut error.into_bytes());
                Err(SecretError::NotUtf8 {
                    reference: self.clone(),
                })
            }
        }
    }
}

/// Reads at most `max_len + 1` bytes, so an oversized file is detected
/// without reading all of it.
fn read_file(path: &Path, options: &ResolveOptions) -> Result<Vec<u8>, SecretError> {
    let read_error = |source| SecretError::FileRead {
        path: path.to_path_buf(),
        source,
    };
    let file = File::open(path).map_err(read_error)?;
    let metadata = file.metadata().map_err(read_error)?;
    if !metadata.is_file() {
        return Err(SecretError::NotAFile {
            path: path.to_path_buf(),
        });
    }
    if options.check_file_permissions {
        check_permissions(path, &metadata)?;
    }
    let mut bytes = Vec::new();
    if let Err(source) = file
        .take(limit_plus_one(options.max_len))
        .read_to_end(&mut bytes)
    {
        wipe(&mut bytes);
        return Err(read_error(source));
    }
    Ok(bytes)
}

fn limit_plus_one(max_len: usize) -> u64 {
    u64::try_from(max_len).unwrap_or(u64::MAX).saturating_add(1)
}

#[cfg(unix)]
fn check_permissions(path: &Path, metadata: &std::fs::Metadata) -> Result<(), SecretError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(SecretError::InsecurePermissions {
            path: path.to_path_buf(),
            mode,
        });
    }
    Ok(())
}

#[cfg(not(unix))]
#[expect(clippy::unnecessary_wraps, reason = "same signature as the unix check")]
const fn check_permissions(_path: &Path, _metadata: &std::fs::Metadata) -> Result<(), SecretError> {
    Ok(())
}

/// How often a running command is polled for exit.
const POLL: Duration = Duration::from_millis(5);

fn run_command(
    program: &str,
    args: &[String],
    options: &ResolveOptions,
) -> Result<Vec<u8>, SecretError> {
    let io_error = |source| SecretError::CommandIo {
        program: program.to_owned(),
        source,
    };
    let timeout = || SecretError::CommandTimeout {
        program: program.to_owned(),
        timeout: options.command_timeout,
    };
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    if let Some(dir) = &options.base_dir {
        command.current_dir(dir);
    }
    // `None`: the timeout is too large to represent, so there is none.
    let deadline = Instant::now().checked_add(options.command_timeout);
    let mut child = command.spawn().map_err(io_error)?;
    let Some(stdout) = child.stdout.take() else {
        kill(&mut child);
        return Err(io_error(io::Error::other(
            "standard output was not captured",
        )));
    };

    // Read on a thread so a chatty program cannot fill the pipe and stall
    // the exit poll below. The read stops after `max_len + 1` bytes; the
    // pipe then closes and an over-long writer gets EPIPE.
    let limit = limit_plus_one(options.max_len);
    let (output_tx, output_rx) = mpsc::channel();
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stdout.take(limit).read_to_end(&mut bytes);
        let message = match result {
            Ok(_) => Ok(bytes),
            Err(error) => {
                wipe(&mut bytes);
                Err(error)
            }
        };
        // The receiver is gone only after a timeout; drop the output then.
        if let Err(mpsc::SendError(Ok(mut bytes))) = output_tx.send(message) {
            wipe(&mut bytes);
        }
    });

    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if deadline.is_some_and(|deadline| Instant::now() >= deadline) => {
                kill(&mut child);
                return Err(timeout());
            }
            Ok(None) => thread::sleep(POLL),
            Err(error) => {
                kill(&mut child);
                return Err(io_error(error));
            }
        }
    };
    // A grandchild may still hold the pipe open; wait no longer than the deadline.
    let output = deadline.map_or_else(
        || output_rx.recv().ok(),
        |deadline| {
            output_rx
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .ok()
        },
    );
    let Some(result) = output else {
        return Err(timeout());
    };
    let mut bytes = result.map_err(io_error)?;
    if !status.success() {
        wipe(&mut bytes);
        return Err(SecretError::CommandFailed {
            program: program.to_owned(),
            status,
        });
    }
    Ok(bytes)
}

fn kill(child: &mut std::process::Child) {
    // Errors mean the child already exited; reap it either way.
    let _ = child.kill();
    let _ = child.wait();
}

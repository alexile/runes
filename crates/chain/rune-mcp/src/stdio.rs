//! [`StdioServer`]: how to spawn a local MCP server (`stdio` feature).

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::PathBuf;
use std::process::Stdio;

use crate::Error;

/// A local MCP server to spawn and talk to over stdin/stdout, for
/// [`McpClient::spawn`](crate::McpClient::spawn).
///
/// The process is started directly from `program` and `args`, never
/// through a shell, so arguments are not word-split or expanded. Its
/// environment is **cleared**: it sees only the variables given with
/// [`env`](Self::env) (pass `PATH` yourself if the server needs it), so
/// API keys and tokens in your own environment do not leak to it. Its
/// stderr is discarded unless [`inherit_stderr`](Self::inherit_stderr) is
/// set. The process is killed when the client is dropped or closed.
///
/// `Debug` shows the variable names, never their values.
///
/// ```
/// use rune_mcp::StdioServer;
///
/// let server = StdioServer::new("uvx")
///     .args(["mcp-server-fetch", "--ignore-robots-txt"])
///     .env("PATH", "/usr/local/bin:/usr/bin:/bin")
///     .env("API_TOKEN", "secret");
/// let shown = format!("{server:?}");
/// assert!(shown.contains("API_TOKEN") && !shown.contains("secret"));
/// ```
#[derive(Clone)]
pub struct StdioServer {
    program: OsString,
    args: Vec<OsString>,
    env: Vec<(OsString, OsString)>,
    current_dir: Option<PathBuf>,
    inherit_stderr: bool,
}

impl fmt::Debug for StdioServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StdioServer")
            .field("program", &self.program)
            .field("args", &self.args)
            .field("env", &self.env.iter().map(|(k, _)| k).collect::<Vec<_>>())
            .field("current_dir", &self.current_dir)
            .field("inherit_stderr", &self.inherit_stderr)
            .finish()
    }
}

impl StdioServer {
    /// Run `program` (a path, or a name looked up in the `PATH` you pass
    /// with [`env`](Self::env), else in this process's `PATH`).
    #[must_use]
    pub fn new(program: impl AsRef<OsStr>) -> Self {
        Self {
            program: program.as_ref().to_owned(),
            args: Vec::new(),
            env: Vec::new(),
            current_dir: None,
            inherit_stderr: false,
        }
    }

    /// Add one argument.
    #[must_use]
    pub fn arg(mut self, arg: impl AsRef<OsStr>) -> Self {
        self.args.push(arg.as_ref().to_owned());
        self
    }

    /// Add arguments.
    #[must_use]
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.args
            .extend(args.into_iter().map(|a| a.as_ref().to_owned()));
        self
    }

    /// Give the process one environment variable.
    #[must_use]
    pub fn env(mut self, key: impl AsRef<OsStr>, value: impl AsRef<OsStr>) -> Self {
        self.env
            .push((key.as_ref().to_owned(), value.as_ref().to_owned()));
        self
    }

    /// Give the process several environment variables, for example the
    /// allowlisted subset of your own:
    /// `.envs(std::env::vars_os().filter(|(k, _)| k == "PATH" || k == "HOME"))`.
    #[must_use]
    pub fn envs<I, K, V>(mut self, vars: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        self.env.extend(
            vars.into_iter()
                .map(|(k, v)| (k.as_ref().to_owned(), v.as_ref().to_owned())),
        );
        self
    }

    /// Run the process in `dir`.
    #[must_use]
    pub fn current_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.current_dir = Some(dir.into());
        self
    }

    /// Pass the server's stderr through to this process's (default: off,
    /// stderr is discarded).
    #[must_use]
    pub const fn inherit_stderr(mut self, on: bool) -> Self {
        self.inherit_stderr = on;
        self
    }

    /// The command that [`McpClient::spawn`](crate::McpClient::spawn)
    /// runs: cleared environment plus the given variables,
    /// `kill_on_drop`. Stdin and stdout are set up by the transport.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] for an empty program or a variable name
    /// that is empty or contains `=` or NUL.
    pub fn command(&self) -> Result<tokio::process::Command, Error> {
        if self.program.is_empty() {
            return Err(Error::InvalidConfig("empty program name".to_owned()));
        }
        for (key, _) in &self.env {
            let bad = key.is_empty() || key.as_encoded_bytes().iter().any(|&b| b == b'=' || b == 0);
            if bad {
                return Err(Error::InvalidConfig(format!(
                    "invalid environment variable name {:?}",
                    key.to_string_lossy()
                )));
            }
        }
        let mut command = tokio::process::Command::new(&self.program);
        command
            .args(&self.args)
            .env_clear()
            .envs(self.env.iter().map(|(k, v)| (k, v)))
            .kill_on_drop(true);
        if let Some(dir) = &self.current_dir {
            command.current_dir(dir);
        }
        Ok(command)
    }

    pub(crate) fn stderr_mode(&self) -> Stdio {
        if self.inherit_stderr {
            Stdio::inherit()
        } else {
            Stdio::null()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_configuration() {
        assert!(StdioServer::new("").command().is_err());
        assert!(StdioServer::new("x").env("A=B", "1").command().is_err());
        assert!(StdioServer::new("x").env("", "1").command().is_err());
        assert!(StdioServer::new("x").env("OK", "1").command().is_ok());
    }

    #[test]
    fn command_lists_only_given_variables() {
        let cmd = StdioServer::new("prog")
            .args(["a", "b c"])
            .env("ONLY", "1")
            .command()
            .unwrap();
        let std = cmd.as_std();
        assert_eq!(std.get_program(), "prog");
        assert_eq!(std.get_args().collect::<Vec<_>>(), ["a", "b c"]);
        let envs: Vec<_> = std.get_envs().collect();
        assert_eq!(envs, [(OsStr::new("ONLY"), Some(OsStr::new("1")))]);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn environment_is_cleared() {
        // `env` prints exactly the environment it was given.
        let Ok(output) = StdioServer::new("/usr/bin/env")
            .env("VISIBLE", "yes")
            .command()
            .unwrap()
            .output()
            .await
        else {
            return; // no /usr/bin/env on this system
        };
        let printed = String::from_utf8_lossy(&output.stdout);
        assert_eq!(printed.trim(), "VISIBLE=yes");
    }
}

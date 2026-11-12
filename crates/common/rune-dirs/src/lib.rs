//! Per-app config, cache, data and state directories (XDG, macOS,
//! Windows) from a caller-supplied environment.
//!
//! [`AppDirs`] resolves the four per-user directories an application
//! usually needs, namespaced by the application's name:
//!
//! | [`DirKind`] | [`Platform::Xdg`] (Linux, BSD) | [`Platform::MacOs`] | [`Platform::Windows`] |
//! | ----------- | ------------------------------ | ------------------- | --------------------- |
//! | `Config`    | `$XDG_CONFIG_HOME/<app>`, else `~/.config/<app>`     | `~/Library/Application Support/<app>`       | `%APPDATA%\<app>\config`     |
//! | `Data`      | `$XDG_DATA_HOME/<app>`, else `~/.local/share/<app>`  | `~/Library/Application Support/<app>`       | `%APPDATA%\<app>\data`       |
//! | `State`     | `$XDG_STATE_HOME/<app>`, else `~/.local/state/<app>` | `~/Library/Application Support/<app>/state` | `%LOCALAPPDATA%\<app>\state` |
//! | `Cache`     | `$XDG_CACHE_HOME/<app>`, else `~/.cache/<app>`       | `~/Library/Caches/<app>`                    | `%LOCALAPPDATA%\<app>\cache` |
//!
//! `~` is `$HOME`. Variables that are unset, empty or hold a relative
//! path are ignored, as the [XDG Base Directory specification] requires;
//! a directory whose variables are all missing is unresolved and reported
//! as [`Error::Unresolved`] when asked for.
//!
//! The library never reads the environment: every function takes a
//! lookup function, `|name| std::env::var(name).ok()` in a program and a
//! fixed map in tests. It touches the file system only in
//! [`AppDirs::ensure`].
//!
//! [XDG Base Directory specification]: https://specifications.freedesktop.org/basedir-spec/latest/
//!
//! # Example
//!
//! ```
//! use std::path::Path;
//! use rune_dirs::{AppDirs, DirKind, Platform};
//!
//! let env = |name: &str| match name {
//!     "HOME" => Some("/home/ada".to_owned()),
//!     "XDG_CACHE_HOME" => Some("/var/cache/ada".to_owned()),
//!     _ => None,
//! };
//! let dirs = AppDirs::for_platform(Platform::Xdg, "myapp", env)?;
//! assert_eq!(dirs.config_dir()?, Path::new("/home/ada/.config/myapp"));
//! assert_eq!(dirs.cache_dir()?, Path::new("/var/cache/ada/myapp"));
//! assert_eq!(
//!     dirs.file(DirKind::Config, "myapp.toml")?,
//!     Path::new("/home/ada/.config/myapp/myapp.toml"),
//! );
//!
//! // A command-line flag can override one directory.
//! let dirs = dirs.with_dir(DirKind::Cache, "/tmp/myapp-cache");
//! assert_eq!(dirs.cache_dir()?, Path::new("/tmp/myapp-cache"));
//!
//! // Without HOME nothing resolves; the error says what to set.
//! let bare = AppDirs::for_platform(Platform::Xdg, "myapp", |_| None)?;
//! assert_eq!(
//!     bare.data_dir().unwrap_err().to_string(),
//!     "cannot locate the data directory for `myapp`: set XDG_DATA_HOME or HOME",
//! );
//! # Ok::<(), rune_dirs::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::fmt;
use std::io;
use std::path::{Component, Path, PathBuf};

/// Errors returned by this crate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// An application or file name is not a single plain path component
    /// (it is empty, `.` or `..`, or contains a separator).
    #[error("`{name}` is not a valid {what} name: it must be a single path component")]
    InvalidName {
        /// The rejected name.
        name: String,
        /// What the name was for: `"application"` or `"file"`.
        what: &'static str,
    },
    /// The environment does not locate this directory.
    #[error("cannot locate the {kind} directory for `{app}`: set {vars}")]
    Unresolved {
        /// The directory asked for.
        kind: DirKind,
        /// The application name.
        app: String,
        /// The variables that would locate it, such as
        /// `"XDG_CONFIG_HOME or HOME"`.
        vars: &'static str,
    },
    /// Creating the directory failed.
    #[error("cannot create {kind} directory {}: {source}", path.display())]
    Create {
        /// The directory being created.
        kind: DirKind,
        /// Its path.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
}

/// Operating-system conventions for per-user directories.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Platform {
    /// XDG base directories (Linux, BSD and other Unix).
    Xdg,
    /// macOS: `~/Library/...`.
    MacOs,
    /// Windows: `%APPDATA%` and `%LOCALAPPDATA%`.
    Windows,
}

impl Platform {
    /// The platform this program was compiled for.
    #[must_use]
    pub const fn current() -> Self {
        if cfg!(windows) {
            Self::Windows
        } else if cfg!(target_os = "macos") {
            Self::MacOs
        } else {
            Self::Xdg
        }
    }

    /// Whether `path` is absolute by this platform's rules, regardless of
    /// the host (so tests behave the same everywhere): a leading `/` on
    /// Unix, a drive (`C:\`) or UNC (`\\server`) prefix on Windows.
    #[must_use]
    pub fn is_absolute(self, path: &Path) -> bool {
        let text = path.to_string_lossy();
        match self {
            Self::Xdg | Self::MacOs => text.starts_with('/'),
            Self::Windows => {
                let bytes = text.as_bytes();
                text.starts_with(r"\\")
                    || (bytes.len() >= 3
                        && bytes[0].is_ascii_alphabetic()
                        && bytes[1] == b':'
                        && matches!(bytes[2], b'\\' | b'/'))
            }
        }
    }
}

/// A kind of per-user application directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum DirKind {
    /// User-edited configuration.
    Config,
    /// Data the application keeps: databases, downloaded packs.
    Data,
    /// State worth keeping across runs but not worth backing up: logs,
    /// history, checkpoints.
    State,
    /// Regenerable cache; safe to delete.
    Cache,
}

impl DirKind {
    /// Every kind, in declaration order.
    pub const ALL: [Self; 4] = [Self::Config, Self::Data, Self::State, Self::Cache];

    /// A lowercase name: `"config"`, `"data"`, `"state"` or `"cache"`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Config => "config",
            Self::Data => "data",
            Self::State => "state",
            Self::Cache => "cache",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::Config => 0,
            Self::Data => 1,
            Self::State => 2,
            Self::Cache => 3,
        }
    }

    /// The variables that locate this directory on `platform`, for error
    /// messages.
    const fn vars(self, platform: Platform) -> &'static str {
        match (platform, self) {
            (Platform::Xdg, Self::Config) => "XDG_CONFIG_HOME or HOME",
            (Platform::Xdg, Self::Data) => "XDG_DATA_HOME or HOME",
            (Platform::Xdg, Self::State) => "XDG_STATE_HOME or HOME",
            (Platform::Xdg, Self::Cache) => "XDG_CACHE_HOME or HOME",
            (Platform::MacOs, _) => "HOME",
            (Platform::Windows, Self::Config | Self::Data) => "APPDATA",
            (Platform::Windows, Self::State | Self::Cache) => "LOCALAPPDATA",
        }
    }
}

impl fmt::Display for DirKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The per-user directory of `kind` for `app` on `platform`, or `None`
/// when `app` is not a plain name or the environment does not locate it.
///
/// `env` looks up environment variables (`HOME`, `XDG_*_HOME`, `APPDATA`,
/// `LOCALAPPDATA`); the library never reads the environment itself.
///
/// ```
/// use rune_dirs::{user_dir, DirKind, Platform};
///
/// let env = |name: &str| (name == "APPDATA").then(|| r"C:\Users\ada\AppData\Roaming".to_owned());
/// let dir = user_dir(Platform::Windows, DirKind::Config, "myapp", env).unwrap();
/// assert!(dir.ends_with("config"));
/// assert_eq!(user_dir(Platform::Windows, DirKind::Cache, "myapp", env), None);
/// ```
#[must_use]
pub fn user_dir(
    platform: Platform,
    kind: DirKind,
    app: &str,
    env: impl Fn(&str) -> Option<String>,
) -> Option<PathBuf> {
    if !is_plain_component(app) {
        return None;
    }
    let absolute = |name: &str| {
        env(name)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .filter(|path| platform.is_absolute(path))
    };
    let xdg = |var: &str, fallback: &[&str]| {
        absolute(var).or_else(|| {
            absolute("HOME").map(|home| fallback.iter().fold(home, |dir, part| dir.join(part)))
        })
    };
    let dir = match (platform, kind) {
        (Platform::Xdg, DirKind::Config) => xdg("XDG_CONFIG_HOME", &[".config"])?.join(app),
        (Platform::Xdg, DirKind::Data) => xdg("XDG_DATA_HOME", &[".local", "share"])?.join(app),
        (Platform::Xdg, DirKind::State) => xdg("XDG_STATE_HOME", &[".local", "state"])?.join(app),
        (Platform::Xdg, DirKind::Cache) => xdg("XDG_CACHE_HOME", &[".cache"])?.join(app),
        (Platform::MacOs, kind) => {
            let library = absolute("HOME")?.join("Library");
            match kind {
                DirKind::Cache => library.join("Caches").join(app),
                DirKind::State => library.join("Application Support").join(app).join("state"),
                DirKind::Config | DirKind::Data => library.join("Application Support").join(app),
            }
        }
        (Platform::Windows, DirKind::Config) => absolute("APPDATA")?.join(app).join("config"),
        (Platform::Windows, DirKind::Data) => absolute("APPDATA")?.join(app).join("data"),
        (Platform::Windows, DirKind::State) => absolute("LOCALAPPDATA")?.join(app).join("state"),
        (Platform::Windows, DirKind::Cache) => absolute("LOCALAPPDATA")?.join(app).join("cache"),
    };
    Some(dir)
}

/// The resolved per-user directories of one application.
///
/// Resolution happens once, in [`AppDirs::new`] or
/// [`AppDirs::for_platform`]; an unresolved directory is reported only
/// when asked for, so a program that never touches its cache does not
/// fail for want of `LOCALAPPDATA`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppDirs {
    platform: Platform,
    app: String,
    dirs: [Option<PathBuf>; 4],
}

impl AppDirs {
    /// The directories of `app` on the current platform.
    ///
    /// `env` looks up environment variables; pass
    /// `|name| std::env::var(name).ok()` in a program.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidName`] when `app` is not a single plain path
    /// component.
    pub fn new(app: &str, env: impl Fn(&str) -> Option<String>) -> Result<Self, Error> {
        Self::for_platform(Platform::current(), app, env)
    }

    /// The directories of `app` under `platform`'s conventions.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidName`] when `app` is not a single plain path
    /// component.
    pub fn for_platform(
        platform: Platform,
        app: &str,
        env: impl Fn(&str) -> Option<String>,
    ) -> Result<Self, Error> {
        if !is_plain_component(app) {
            return Err(Error::InvalidName {
                name: app.to_owned(),
                what: "application",
            });
        }
        let dirs = DirKind::ALL.map(|kind| user_dir(platform, kind, app, &env));
        Ok(Self {
            platform,
            app: app.to_owned(),
            dirs,
        })
    }

    /// Replaces one directory, for example with the value of a
    /// `--cache-dir` flag. The path is used as given.
    #[must_use]
    pub fn with_dir(mut self, kind: DirKind, dir: impl Into<PathBuf>) -> Self {
        self.dirs[kind.index()] = Some(dir.into());
        self
    }

    /// The application name.
    #[must_use]
    pub fn app(&self) -> &str {
        &self.app
    }

    /// The platform whose conventions were used.
    #[must_use]
    pub const fn platform(&self) -> Platform {
        self.platform
    }

    /// The directory of `kind`.
    ///
    /// # Errors
    ///
    /// [`Error::Unresolved`] when the environment did not locate it.
    pub fn dir(&self, kind: DirKind) -> Result<&Path, Error> {
        self.dirs[kind.index()]
            .as_deref()
            .ok_or_else(|| Error::Unresolved {
                kind,
                app: self.app.clone(),
                vars: kind.vars(self.platform),
            })
    }

    /// The [`DirKind::Config`] directory. See [`dir`](Self::dir).
    pub fn config_dir(&self) -> Result<&Path, Error> {
        self.dir(DirKind::Config)
    }

    /// The [`DirKind::Data`] directory. See [`dir`](Self::dir).
    pub fn data_dir(&self) -> Result<&Path, Error> {
        self.dir(DirKind::Data)
    }

    /// The [`DirKind::State`] directory. See [`dir`](Self::dir).
    pub fn state_dir(&self) -> Result<&Path, Error> {
        self.dir(DirKind::State)
    }

    /// The [`DirKind::Cache`] directory. See [`dir`](Self::dir).
    pub fn cache_dir(&self) -> Result<&Path, Error> {
        self.dir(DirKind::Cache)
    }

    /// The file `name` inside the directory of `kind`, such as
    /// `config.toml` in the config directory.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidName`] when `name` is not a single plain path
    /// component (so it cannot escape the directory), and
    /// [`Error::Unresolved`] as for [`dir`](Self::dir).
    pub fn file(&self, kind: DirKind, name: &str) -> Result<PathBuf, Error> {
        if !is_plain_component(name) {
            return Err(Error::InvalidName {
                name: name.to_owned(),
                what: "file",
            });
        }
        Ok(self.dir(kind)?.join(name))
    }

    /// The directory of `kind`, created (with its parents) if missing.
    ///
    /// On Unix, directories this call creates get mode `0700`, so other
    /// users cannot read the application's files; existing directories
    /// are left as they are.
    ///
    /// # Errors
    ///
    /// [`Error::Unresolved`] as for [`dir`](Self::dir), and
    /// [`Error::Create`] when creating it fails or the path exists but is
    /// not a directory.
    pub fn ensure(&self, kind: DirKind) -> Result<&Path, Error> {
        let dir = self.dir(kind)?;
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder.create(dir).map_err(|source| Error::Create {
            kind,
            path: dir.to_path_buf(),
            source,
        })?;
        Ok(dir)
    }
}

/// Whether `name` is a single normal path component on every platform:
/// not empty, not `.` or `..`, and without `/` or `\`.
#[must_use]
pub fn is_plain_component(name: &str) -> bool {
    !name.contains(['/', '\\'])
        && matches!(
            Path::new(name).components().collect::<Vec<_>>().as_slice(),
            [Component::Normal(_)]
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| {
            pairs
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| (*v).to_owned())
        }
    }

    fn dirs(platform: Platform, pairs: &[(&str, &str)]) -> AppDirs {
        AppDirs::for_platform(platform, "app", env(pairs)).unwrap()
    }

    #[test]
    fn xdg_home_fallbacks() {
        let d = dirs(Platform::Xdg, &[("HOME", "/home/u")]);
        assert_eq!(d.config_dir().unwrap(), Path::new("/home/u/.config/app"));
        assert_eq!(d.data_dir().unwrap(), Path::new("/home/u/.local/share/app"));
        assert_eq!(
            d.state_dir().unwrap(),
            Path::new("/home/u/.local/state/app")
        );
        assert_eq!(d.cache_dir().unwrap(), Path::new("/home/u/.cache/app"));
    }

    #[test]
    fn xdg_variables_win_when_absolute() {
        let d = dirs(
            Platform::Xdg,
            &[
                ("HOME", "/home/u"),
                ("XDG_CONFIG_HOME", "/c"),
                ("XDG_DATA_HOME", "/d"),
                ("XDG_STATE_HOME", "/s"),
                ("XDG_CACHE_HOME", "relative/cache"),
            ],
        );
        assert_eq!(d.config_dir().unwrap(), Path::new("/c/app"));
        assert_eq!(d.data_dir().unwrap(), Path::new("/d/app"));
        assert_eq!(d.state_dir().unwrap(), Path::new("/s/app"));
        // Relative XDG values are ignored, per the specification.
        assert_eq!(d.cache_dir().unwrap(), Path::new("/home/u/.cache/app"));
    }

    #[test]
    fn xdg_without_home_is_unresolved() {
        let d = dirs(Platform::Xdg, &[("HOME", ""), ("XDG_CACHE_HOME", "/c")]);
        assert_eq!(d.cache_dir().unwrap(), Path::new("/c/app"));
        let err = d.config_dir().unwrap_err();
        assert!(matches!(
            err,
            Error::Unresolved {
                kind: DirKind::Config,
                vars: "XDG_CONFIG_HOME or HOME",
                ..
            }
        ));
    }

    #[test]
    fn macos_layout() {
        let d = dirs(
            Platform::MacOs,
            &[("HOME", "/Users/u"), ("XDG_CONFIG_HOME", "/x")],
        );
        let support = Path::new("/Users/u/Library/Application Support/app");
        assert_eq!(d.config_dir().unwrap(), support);
        assert_eq!(d.data_dir().unwrap(), support);
        assert_eq!(d.state_dir().unwrap(), support.join("state"));
        assert_eq!(
            d.cache_dir().unwrap(),
            Path::new("/Users/u/Library/Caches/app")
        );
        assert!(dirs(Platform::MacOs, &[]).config_dir().is_err());
    }

    #[test]
    fn windows_layout() {
        let roaming = r"C:\Users\u\AppData\Roaming";
        let local = r"C:\Users\u\AppData\Local";
        let d = dirs(
            Platform::Windows,
            &[
                ("APPDATA", roaming),
                ("LOCALAPPDATA", local),
                ("HOME", "/h"),
            ],
        );
        let join = |base: &str, last: &str| PathBuf::from(base).join("app").join(last);
        assert_eq!(d.config_dir().unwrap(), join(roaming, "config"));
        assert_eq!(d.data_dir().unwrap(), join(roaming, "data"));
        assert_eq!(d.state_dir().unwrap(), join(local, "state"));
        assert_eq!(d.cache_dir().unwrap(), join(local, "cache"));

        let only_roaming = dirs(
            Platform::Windows,
            &[("APPDATA", roaming), ("LOCALAPPDATA", "rel")],
        );
        assert!(only_roaming.config_dir().is_ok());
        assert_eq!(
            only_roaming.cache_dir().unwrap_err().to_string(),
            "cannot locate the cache directory for `app`: set LOCALAPPDATA"
        );
        // UNC paths are absolute.
        let unc = dirs(Platform::Windows, &[("APPDATA", r"\\server\share")]);
        assert!(unc.config_dir().is_ok());
    }

    #[test]
    fn rejects_non_plain_names() {
        for app in ["", ".", "..", "a/b", r"a\b"] {
            let err =
                AppDirs::for_platform(Platform::Xdg, app, env(&[("HOME", "/h")])).unwrap_err();
            assert!(
                matches!(
                    err,
                    Error::InvalidName {
                        what: "application",
                        ..
                    }
                ),
                "{app:?}"
            );
            assert_eq!(
                user_dir(Platform::Xdg, DirKind::Config, app, env(&[("HOME", "/h")])),
                None
            );
        }
        let d = dirs(Platform::Xdg, &[("HOME", "/h")]);
        assert_eq!(
            d.file(DirKind::Config, "app.toml").unwrap(),
            Path::new("/h/.config/app/app.toml")
        );
        for file in ["", "..", "../x", "a/b"] {
            assert!(matches!(
                d.file(DirKind::Config, file),
                Err(Error::InvalidName { what: "file", .. })
            ));
        }
    }

    #[test]
    fn overrides_replace_one_dir() {
        let d = dirs(Platform::Xdg, &[]).with_dir(DirKind::Cache, "/override");
        assert_eq!(d.cache_dir().unwrap(), Path::new("/override"));
        assert!(d.config_dir().is_err());
        assert_eq!(d.app(), "app");
        assert_eq!(d.platform(), Platform::Xdg);
    }

    #[test]
    fn current_platform_matches_cfg() {
        let expected = if cfg!(windows) {
            Platform::Windows
        } else if cfg!(target_os = "macos") {
            Platform::MacOs
        } else {
            Platform::Xdg
        };
        assert_eq!(Platform::current(), expected);
    }

    #[test]
    fn ensure_creates_private_dirs_on_demand() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("deep").join("state");
        let d = dirs(Platform::current(), &[]).with_dir(DirKind::State, &state);
        assert!(!state.exists());
        assert_eq!(d.ensure(DirKind::State).unwrap(), state);
        assert!(state.is_dir());
        // Idempotent.
        assert_eq!(d.ensure(DirKind::State).unwrap(), state);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&state).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700);
        }
        // A file in the way is an error naming the path.
        let blocked = tmp.path().join("file");
        std::fs::write(&blocked, b"").unwrap();
        let d = d.with_dir(DirKind::Cache, &blocked);
        assert!(matches!(
            d.ensure(DirKind::Cache),
            Err(Error::Create {
                kind: DirKind::Cache,
                ..
            })
        ));
        // Unresolved stays unresolved.
        assert!(matches!(
            d.ensure(DirKind::Config),
            Err(Error::Unresolved { .. })
        ));
    }

    #[test]
    fn kind_names() {
        let names: Vec<String> = DirKind::ALL.iter().map(ToString::to_string).collect();
        assert_eq!(names, ["config", "data", "state", "cache"]);
    }
}

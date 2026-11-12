//! Conventional per-user config file locations.

use std::path::PathBuf;

use rune_dirs::{DirKind, is_plain_component, user_dir};

/// Operating-system conventions for per-user directories, from
/// [`rune_dirs`]. The config directory is
/// `$XDG_CONFIG_HOME/<app>` (else `$HOME/.config/<app>`) for
/// [`Platform::Xdg`], `$HOME/Library/Application Support/<app>` for
/// [`Platform::MacOs`] and `%APPDATA%\<app>\config` for
/// [`Platform::Windows`].
pub use rune_dirs::Platform;

/// The default per-user config file for `app` on the current platform, for
/// example `~/.config/<app>/<file_name>` on Linux.
///
/// `env` looks up environment variables (`HOME`, `XDG_CONFIG_HOME`,
/// `APPDATA`); pass `|name| std::env::var(name).ok()` in a program and a
/// fixed map in tests. The library never reads the environment itself.
///
/// Returns `None` when the needed variables are unset, empty or not
/// absolute, or when `app` or `file_name` is not a single plain path
/// component (empty, `.`/`..`, or containing a separator).
///
/// ```
/// use rune_config::default_user_config_path;
///
/// let env = |name: &str| (name == "HOME").then(|| "/home/ada".to_owned());
/// if cfg!(target_os = "linux") {
///     assert_eq!(
///         default_user_config_path("myapp", "myapp.toml", env),
///         Some("/home/ada/.config/myapp/myapp.toml".into()),
///     );
/// }
/// ```
#[must_use]
pub fn default_user_config_path(
    app: &str,
    file_name: &str,
    env: impl Fn(&str) -> Option<String>,
) -> Option<PathBuf> {
    user_config_path_for(Platform::current(), app, file_name, env)
}

/// Like [`default_user_config_path`] for an explicit [`Platform`].
#[must_use]
pub fn user_config_path_for(
    platform: Platform,
    app: &str,
    file_name: &str,
    env: impl Fn(&str) -> Option<String>,
) -> Option<PathBuf> {
    if !is_plain_component(file_name) {
        return None;
    }
    Some(user_dir(platform, DirKind::Config, app, env)?.join(file_name))
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

    #[test]
    fn xdg_prefers_config_home_then_home() {
        let both = [("XDG_CONFIG_HOME", "/xdg"), ("HOME", "/home/u")];
        assert_eq!(
            user_config_path_for(Platform::Xdg, "app", "app.toml", env(&both)),
            Some(PathBuf::from("/xdg/app/app.toml"))
        );
        let relative_xdg = [("XDG_CONFIG_HOME", "rel"), ("HOME", "/home/u")];
        assert_eq!(
            user_config_path_for(Platform::Xdg, "app", "app.toml", env(&relative_xdg)),
            Some(PathBuf::from("/home/u/.config/app/app.toml"))
        );
        assert_eq!(
            user_config_path_for(Platform::Xdg, "app", "app.toml", env(&[("HOME", "")])),
            None
        );
    }

    #[test]
    fn macos_and_windows_layouts() {
        assert_eq!(
            user_config_path_for(
                Platform::MacOs,
                "app",
                "a.toml",
                env(&[("HOME", "/Users/u")])
            ),
            Some(PathBuf::from(
                "/Users/u/Library/Application Support/app/a.toml"
            ))
        );
        let windows = user_config_path_for(
            Platform::Windows,
            "app",
            "a.toml",
            env(&[("APPDATA", r"C:\Users\u\AppData\Roaming")]),
        )
        .unwrap();
        let expected = PathBuf::from(r"C:\Users\u\AppData\Roaming")
            .join("app")
            .join("config")
            .join("a.toml");
        assert_eq!(windows, expected);
        assert_eq!(
            user_config_path_for(
                Platform::Windows,
                "app",
                "a.toml",
                env(&[("APPDATA", "rel")])
            ),
            None
        );
    }

    #[test]
    fn rejects_non_plain_names() {
        let home = [("HOME", "/h")];
        for (app, file) in [
            ("", "a"),
            ("..", "a"),
            ("a/b", "c"),
            ("a", r"..\x"),
            ("a", "."),
        ] {
            assert_eq!(
                user_config_path_for(Platform::Xdg, app, file, env(&home)),
                None,
                "{app:?} {file:?}"
            );
        }
    }

    #[test]
    fn agrees_with_rune_dirs_config_dir() {
        let vars = [
            ("HOME", "/home/u"),
            ("XDG_CONFIG_HOME", "/xdg"),
            ("APPDATA", r"C:\Roaming"),
        ];
        for platform in [Platform::Xdg, Platform::MacOs, Platform::Windows] {
            let dirs = rune_dirs::AppDirs::for_platform(platform, "app", env(&vars)).unwrap();
            assert_eq!(
                user_config_path_for(platform, "app", "app.toml", env(&vars)),
                Some(dirs.file(DirKind::Config, "app.toml").unwrap()),
                "{platform:?}"
            );
        }
    }
}

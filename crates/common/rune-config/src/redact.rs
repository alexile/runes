//! Spotting keys whose values should not be printed.

/// Fragments that mark a key as secret, compared against the key with
/// case and punctuation removed (`DB_PASSWORD` and `db.password` both
/// become `dbpassword`).
const SECRET_MARKERS: &[&str] = &[
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "apikey",
    "privatekey",
    "accesskey",
    "signingkey",
    "encryptionkey",
    "credential",
    "authorization",
    "cookie",
    "dsn",
    "connectionstring",
    "salt",
];

/// The text shown in place of a hidden value.
pub const REDACTED: &str = "<redacted>";

/// Whether `key` looks like it names a secret, so its value should be kept
/// out of `Debug` output, reports and error messages.
///
/// The check is a heuristic on the name only: after removing everything
/// but ASCII letters and digits and lower-casing, the key must contain one
/// of `password`, `passwd`, `passphrase`, `secret`, `token`, `apikey`,
/// `privatekey`, `accesskey`, `signingkey`, `encryptionkey`, `credential`,
/// `authorization`, `cookie`, `dsn`, `connectionstring` or `salt`. It works
/// for environment variable names and dotted config keys alike.
///
/// ```
/// use rune_config::is_secret_key;
///
/// assert!(is_secret_key("APP_DB__PASSWORD"));
/// assert!(is_secret_key("github.api-key"));
/// assert!(is_secret_key("session_token"));
/// assert!(!is_secret_key("scan.rate_limit"));
/// ```
#[must_use]
pub fn is_secret_key(key: &str) -> bool {
    let folded: String = key
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect();
    SECRET_MARKERS.iter().any(|marker| folded.contains(marker))
}

/// Replaces every occurrence of `raw` (and of `raw` trimmed) in `message`
/// when `secret` is set.
pub fn scrub(message: String, raw: &str, secret: bool) -> String {
    if !secret {
        return message;
    }
    // Parsers often quote the trimmed value rather than the raw one.
    let mut message = message;
    for needle in [raw, raw.trim()] {
        if !needle.is_empty() && message.contains(needle) {
            message = message.replace(needle, REDACTED);
        }
    }
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spots_common_secret_names() {
        for key in [
            "PASSWORD",
            "db.password",
            "AWS_SECRET_ACCESS_KEY",
            "githubToken",
            "Api-Key",
            "SENTRY_DSN",
            "private_key_pem",
            "client.credentials",
        ] {
            assert!(is_secret_key(key), "{key}");
        }
        for key in ["HOST", "port", "author", "scan.rate_limit", "PWD", "keys"] {
            assert!(!is_secret_key(key), "{key}");
        }
    }

    #[test]
    fn scrub_only_touches_secrets() {
        assert_eq!(
            scrub("bad `hunter2`".into(), "hunter2", true),
            "bad `<redacted>`"
        );
        assert_eq!(scrub("bad `x`".into(), "x", false), "bad `x`");
        assert_eq!(scrub("bad".into(), "", true), "bad");
        assert_eq!(
            scrub("bad `hunter2`".into(), " hunter2\n", true),
            "bad `<redacted>`"
        );
    }
}

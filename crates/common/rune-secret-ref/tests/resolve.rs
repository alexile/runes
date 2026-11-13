//! Each `SecretRef` source resolves, and failures never reveal the secret.

#![allow(clippy::unwrap_used, reason = "test helpers")]

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::Duration;

use rune_secret_ref::{ResolveOptions, SecretError, SecretRef, SecretValue};

const SECRET: &str = "s3cr3t-Value_42";

const fn no_env(_: &str) -> Option<String> {
    None
}

fn reference(text: &str) -> SecretRef {
    text.parse().unwrap()
}

/// Writes a secret file with owner-only permissions.
fn secret_file(dir: &Path, name: &str, contents: &[u8]) -> std::path::PathBuf {
    let path = dir.join(name);
    fs::write(&path, contents).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    path
}

#[test]
fn env_resolves_through_the_callers_lookup() {
    let env: HashMap<&str, &str> = HashMap::from([("API_KEY", SECRET), ("EMPTY", "")]);
    let lookup = |name: &str| env.get(name).map(|value| (*value).to_owned());
    let options = ResolveOptions::default();

    let value = reference("env:API_KEY").resolve(&options, lookup).unwrap();
    assert_eq!(value, SecretValue::new(SECRET));

    for missing in ["env:EMPTY", "env:UNSET"] {
        let error = reference(missing).resolve(&options, lookup).unwrap_err();
        assert!(matches!(error, SecretError::EnvUnset(_)), "{error}");
    }
}

#[test]
fn file_resolves_and_strips_one_newline() {
    let dir = tempfile::tempdir().unwrap();
    let options = ResolveOptions::default();
    for (name, contents, expected) in [
        ("plain", "abc", "abc"),
        ("lf", "abc\n", "abc"),
        ("crlf", "abc\r\n", "abc"),
        ("two", "abc\n\n", "abc\n"),
        ("inner", "line1\nline2\n", "line1\nline2"),
    ] {
        let path = secret_file(dir.path(), name, contents.as_bytes());
        let value = SecretRef::File(path).resolve(&options, no_env).unwrap();
        assert_eq!(value.expose(), expected, "{name}");
    }
}

#[test]
fn relative_file_joins_base_dir() {
    let dir = tempfile::tempdir().unwrap();
    secret_file(dir.path(), "token", SECRET.as_bytes());
    let options = ResolveOptions::default().with_base_dir(dir.path());
    let value = reference("file:token").resolve(&options, no_env).unwrap();
    assert_eq!(value.expose(), SECRET);
}

#[test]
fn file_errors() {
    let dir = tempfile::tempdir().unwrap();
    let options = ResolveOptions::default();

    let missing = SecretRef::File(dir.path().join("nope"));
    assert!(matches!(
        missing.resolve(&options, no_env),
        Err(SecretError::FileRead { .. })
    ));

    let directory = SecretRef::File(dir.path().to_path_buf());
    assert!(matches!(
        directory.resolve(&options, no_env),
        Err(SecretError::NotAFile { .. } | SecretError::FileRead { .. })
    ));

    let empty = SecretRef::File(secret_file(dir.path(), "empty", b"\n"));
    assert!(matches!(
        empty.resolve(&options, no_env),
        Err(SecretError::Empty { .. })
    ));

    let binary = SecretRef::File(secret_file(dir.path(), "binary", &[0xff, 0xfe]));
    assert!(matches!(
        binary.resolve(&options, no_env),
        Err(SecretError::NotUtf8 { .. })
    ));

    let big = SecretRef::File(secret_file(dir.path(), "big", &[b'a'; 33]));
    let small = ResolveOptions::default().with_max_len(32);
    assert!(matches!(
        big.resolve(&small, no_env),
        Err(SecretError::TooLarge { limit: 32, .. })
    ));
    // Exactly at the limit, with the newline beyond it, is fine.
    let edge = SecretRef::File(secret_file(dir.path(), "edge", &[b'a'; 32]));
    assert_eq!(edge.resolve(&small, no_env).unwrap().expose().len(), 32);
}

/// A FIFO with no writer would block `open` forever.
#[cfg(unix)]
#[test]
fn fifo_is_refused_without_blocking() {
    let dir = tempfile::tempdir().unwrap();
    let fifo = dir.path().join("fifo");
    let made = std::process::Command::new("mkfifo")
        .arg("-m")
        .arg("600")
        .arg(&fifo)
        .status();
    if !made.is_ok_and(|status| status.success()) {
        eprintln!("skipping: mkfifo is not available");
        return;
    }
    let (send, receive) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let result = SecretRef::File(fifo).resolve(&ResolveOptions::default(), no_env);
        let _ = send.send(result);
    });
    let result = receive
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("resolving a FIFO blocked");
    assert!(
        matches!(result, Err(SecretError::NotAFile { .. })),
        "{result:?}"
    );
}

#[cfg(unix)]
#[test]
fn file_readable_by_others_is_refused_unless_allowed() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = secret_file(dir.path(), "open", SECRET.as_bytes());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    let reference = SecretRef::File(path);

    let error = reference
        .resolve(&ResolveOptions::default(), no_env)
        .unwrap_err();
    assert!(matches!(
        error,
        SecretError::InsecurePermissions { mode: 0o644, .. }
    ));
    assert!(error.to_string().contains("chmod 600"));

    let lax = ResolveOptions::default().with_check_file_permissions(false);
    assert_eq!(reference.resolve(&lax, no_env).unwrap().expose(), SECRET);
}

#[test]
fn command_is_disabled_by_default() {
    let error = reference("cmd:echo hi")
        .resolve(&ResolveOptions::default(), no_env)
        .unwrap_err();
    assert!(matches!(error, SecretError::CommandDisabled { ref program } if program == "echo"));
}

#[cfg(unix)]
mod command {
    use super::*;

    fn allowed() -> ResolveOptions {
        ResolveOptions::default().with_allow_command(true)
    }

    fn sh(script: &str) -> SecretRef {
        SecretRef::command(["sh", "-c", script]).unwrap()
    }

    #[test]
    fn resolves_standard_output() {
        let value = sh(&format!("printf '{SECRET}\\n'"))
            .resolve(&allowed(), no_env)
            .unwrap();
        assert_eq!(value.expose(), SECRET);
        let value = reference("cmd:printf abc")
            .resolve(&allowed(), no_env)
            .unwrap();
        assert_eq!(value.expose(), "abc");
    }

    #[test]
    fn runs_in_base_dir_without_a_shell() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("token"), SECRET).unwrap();
        let options = allowed().with_base_dir(dir.path());
        let value = reference("cmd:cat token")
            .resolve(&options, no_env)
            .unwrap();
        assert_eq!(value.expose(), SECRET);
        // No shell: `$HOME` reaches `printf` literally.
        let value = reference("cmd:printf $HOME")
            .resolve(&options, no_env)
            .unwrap();
        assert_eq!(value.expose(), "$HOME");
    }

    #[test]
    fn failure_reports_status_not_output() {
        let error = sh(&format!("printf '{SECRET}'; exit 3"))
            .resolve(&allowed(), no_env)
            .unwrap_err();
        assert!(matches!(error, SecretError::CommandFailed { .. }));
        assert!(!error.to_string().contains(SECRET));
        assert!(!format!("{error:?}").contains(SECRET));
    }

    #[test]
    fn missing_program_is_an_io_error() {
        let error = reference("cmd:/nonexistent/rune-secret-ref-test")
            .resolve(&allowed(), no_env)
            .unwrap_err();
        assert!(matches!(error, SecretError::CommandIo { .. }));
    }

    #[test]
    fn slow_command_is_killed() {
        let options = allowed().with_command_timeout(Duration::from_millis(100));
        let started = std::time::Instant::now();
        let error = reference("cmd:sleep 5")
            .resolve(&options, no_env)
            .unwrap_err();
        assert!(matches!(error, SecretError::CommandTimeout { .. }));
        assert!(started.elapsed() < Duration::from_secs(4));
    }

    #[test]
    fn oversized_and_empty_output_are_rejected() {
        let options = allowed().with_max_len(16);
        let error = sh("yes x | head -c 100000")
            .resolve(&options, no_env)
            .unwrap_err();
        assert!(
            matches!(error, SecretError::TooLarge { limit: 16, .. }),
            "{error}"
        );
        let error = reference("cmd:true")
            .resolve(&allowed(), no_env)
            .unwrap_err();
        assert!(matches!(error, SecretError::Empty { .. }));
    }
}

#[test]
fn provider_schemes_are_unsupported_here() {
    for text in ["keychain:svc/acct", "vault:kv/app"] {
        let error = reference(text)
            .resolve(&ResolveOptions::default(), no_env)
            .unwrap_err();
        assert!(matches!(error, SecretError::Unsupported { .. }), "{text}");
    }
}

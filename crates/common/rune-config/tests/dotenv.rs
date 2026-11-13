//! `.env` files: conformance cases, file checks and layering.

#![allow(clippy::unwrap_used, reason = "test helpers")]

use std::path::PathBuf;

use rune_config::{
    ConfigLoader, Dotenv, DotenvErrorKind, DotenvOptions, EnvMapping, EnvReader, Source,
};
use serde::Deserialize;

fn write(dir: &tempfile::TempDir, name: &str, text: &str) -> PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, text).unwrap();
    path
}

/// Cases in the style of the dotenv test suites shared by the Ruby,
/// Node and Python implementations: input line, expected value.
#[test]
fn common_dotenv_cases() {
    let cases: &[(&str, &str)] = &[
        ("BASIC=basic", "basic"),
        ("AFTER_LINE=after_line", "after_line"),
        ("EMPTY=", ""),
        ("EMPTY_SINGLE_QUOTES=''", ""),
        ("EMPTY_DOUBLE_QUOTES=\"\"", ""),
        ("SINGLE_QUOTES='single_quotes'", "single_quotes"),
        (
            "SINGLE_QUOTES_SPACED='    single quotes    '",
            "    single quotes    ",
        ),
        ("DOUBLE_QUOTES=\"double_quotes\"", "double_quotes"),
        (
            "DOUBLE_QUOTES_SPACED=\"    double quotes    \"",
            "    double quotes    ",
        ),
        (
            "DOUBLE_QUOTES_INSIDE_SINGLE='double \"quotes\" work inside single quotes'",
            "double \"quotes\" work inside single quotes",
        ),
        (
            "SINGLE_QUOTES_INSIDE_DOUBLE=\"single 'quotes' work inside double quotes\"",
            "single 'quotes' work inside double quotes",
        ),
        (
            "EXPAND_NEWLINES=\"expand\\nnew\\nlines\"",
            "expand\nnew\nlines",
        ),
        (
            "DONT_EXPAND_UNQUOTED=dontexpand\\nnewlines",
            "dontexpand\\nnewlines",
        ),
        (
            "DONT_EXPAND_SQUOTED='dontexpand\\nnewlines'",
            "dontexpand\\nnewlines",
        ),
        (
            "INLINE_COMMENTS=inline comments # work #very #well",
            "inline comments",
        ),
        (
            "INLINE_COMMENTS_SINGLE_QUOTES='inline comments outside of #singlequotes' # work",
            "inline comments outside of #singlequotes",
        ),
        (
            "INLINE_COMMENTS_DOUBLE_QUOTES=\"inline comments outside of #doublequotes\" # work",
            "inline comments outside of #doublequotes",
        ),
        ("EQUAL_SIGNS=equals==", "equals=="),
        (
            "RETAIN_INNER_QUOTES={\"foo\": \"bar\"}",
            "{\"foo\": \"bar\"}",
        ),
        (
            "RETAIN_INNER_QUOTES_AS_STRING='{\"foo\": \"bar\"}'",
            "{\"foo\": \"bar\"}",
        ),
        (
            "TRIM_SPACE_FROM_UNQUOTED=    some spaced out string    ",
            "some spaced out string",
        ),
        (
            "USERNAME=therealnerdybeast@example.tld",
            "therealnerdybeast@example.tld",
        ),
        ("    SPACED_KEY = parsed", "parsed"),
        ("export EXPORTED=yes", "yes"),
        (
            "URL=https://example.com/a?b=c#frag",
            "https://example.com/a?b=c#frag",
        ),
    ];
    for (line, expected) in cases {
        let env = Dotenv::parse(line).unwrap_or_else(|e| panic!("{line}: {e}"));
        assert_eq!(env.len(), 1, "{line}");
        assert_eq!(env.entries()[0].value, *expected, "{line}");
    }
}

#[test]
fn multiline_values_and_line_numbers() {
    let text = "A=1\nPRIVATE_KEY=\"-----BEGIN-----\nabc\n-----END-----\"\nB='x\ny'\nC=3\n";
    let env = Dotenv::parse(text).unwrap();
    assert_eq!(
        env.get("PRIVATE_KEY"),
        Some("-----BEGIN-----\nabc\n-----END-----")
    );
    let lines: Vec<_> = env
        .entries()
        .iter()
        .map(|e| (e.key.as_str(), e.line))
        .collect();
    assert_eq!(lines, [("A", 1), ("PRIVATE_KEY", 2), ("B", 5), ("C", 7)]);
}

#[test]
fn file_errors_carry_the_path_and_position() {
    let dir = tempfile::tempdir().unwrap();
    let path = write(&dir, ".env", "OK=1\nBROKEN\n");
    let e = Dotenv::read(&path).unwrap_err();
    assert_eq!((e.line, e.column), (2, 7));
    assert_eq!(
        e.to_string(),
        format!(
            "{}:2:7: expected `=` after the variable name",
            path.display()
        )
    );
    let e = Dotenv::read(dir.path().join("missing.env")).unwrap_err();
    assert!(e.is_not_found());
}

#[test]
fn size_limit_applies_to_files() {
    let dir = tempfile::tempdir().unwrap();
    let path = write(&dir, ".env", "A=0123456789\n");
    let e = DotenvOptions::new().max_size(8).read(&path).unwrap_err();
    assert_eq!(e.kind, DotenvErrorKind::TooLarge(8));
    assert!(DotenvOptions::new().max_size(13).read(&path).is_ok());

    let big = write(&dir, "big.toml", &format!("a = \"{}\"\n", "x".repeat(100)));
    let errors = ConfigLoader::new()
        .max_file_size(50)
        .with_project_file(&big, true)
        .load()
        .unwrap_err();
    assert!(
        errors.issues()[0].message.contains("50-byte limit"),
        "{errors}"
    );
}

#[test]
fn rejects_non_utf8() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(".env");
    std::fs::write(&path, b"A=\xff\n").unwrap();
    assert_eq!(
        Dotenv::read(&path).unwrap_err().kind,
        DotenvErrorKind::NotUtf8
    );
}

#[cfg(unix)]
#[test]
fn world_writable_check_is_opt_in() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = tempfile::tempdir().unwrap();
    let path = write(&dir, ".env", "A=1\n");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert!(Dotenv::read(&path).is_ok());
    let strict = DotenvOptions::new().reject_world_writable(true);
    assert_eq!(
        strict.read(&path).unwrap_err().kind,
        DotenvErrorKind::WorldWritable
    );
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(strict.read(&path).is_ok());
}

#[derive(Debug, Deserialize, PartialEq)]
struct Config {
    host: String,
    port: u16,
    debug: bool,
    db: Db,
}

#[derive(Debug, Deserialize, PartialEq)]
struct Db {
    user: String,
    password: String,
}

#[test]
fn full_layering_with_report() {
    let dir = tempfile::tempdir().unwrap();
    let toml = write(
        &dir,
        "app.toml",
        "host = \"file\"\nport = 81\n[db]\nuser = \"file\"\n",
    );
    let dotenv = write(
        &dir,
        ".env",
        "# local\nAPP_PORT=82\nAPP_DB__USER=dotenv\nAPP_DB__PASSWORD=s3cr3t-value\n",
    );
    let mapping = EnvMapping::new().prefix("APP_");
    let loaded = ConfigLoader::new()
        .with_defaults_toml(
            "host = \"default\"\nport = 80\ndebug = false\n[db]\nuser = \"\"\npassword = \"\"\n",
        )
        .with_project_file(&toml, true)
        .with_dotenv_file(&dotenv, false, &mapping, &DotenvOptions::new())
        .with_env([("APP_DB__USER", "env")], &mapping)
        .with_cli(&rune_config::CliOverrides::new().set("--debug", "debug", true))
        .load()
        .unwrap();
    let config: Config = loaded.deserialize().unwrap();
    assert_eq!(
        config,
        Config {
            host: "file".into(),
            port: 82,
            debug: true,
            db: Db {
                user: "env".into(),
                password: "s3cr3t-value".into()
            },
        }
    );
    assert_eq!(
        loaded.source_of("db.password"),
        Some(&Source::DotenvVar {
            file: Some(dotenv.clone()),
            var: "APP_DB__PASSWORD".into(),
            line: 4
        })
    );

    let report = loaded.report().to_string();
    assert!(!report.contains("s3cr3t"), "{report}");
    assert!(
        report.contains(&format!(
            "db.password = <redacted>  # APP_DB__PASSWORD in {}:4",
            dotenv.display()
        )),
        "{report}"
    );
    assert!(
        report.contains("db.user = \"env\"  # environment variable APP_DB__USER"),
        "{report}"
    );
    assert!(
        report.contains("debug = true  # command-line flag --debug"),
        "{report}"
    );
    assert!(
        report.contains("host = \"file\"  # project file"),
        "{report}"
    );
    assert!(!format!("{loaded:?}").contains("s3cr3t"));

    let custom = loaded.report_with(|key| key == "host").to_string();
    assert!(custom.contains("host = <redacted>"), "{custom}");
}

#[test]
fn dotenv_layer_problems_are_reported() {
    let dir = tempfile::tempdir().unwrap();
    let bad = write(&dir, ".env", "APP_A=1\nAPP B=2\n");
    let mapping = EnvMapping::new().prefix("APP_");
    let errors = ConfigLoader::new()
        .with_dotenv_file(&bad, true, &mapping, &DotenvOptions::new())
        .with_dotenv_file(
            dir.path().join("absent.env"),
            false,
            &mapping,
            &DotenvOptions::new(),
        )
        .with_dotenv_file(
            dir.path().join("needed.env"),
            true,
            &mapping,
            &DotenvOptions::new(),
        )
        .load()
        .unwrap_err();
    let issues = errors.issues();
    assert_eq!(issues.len(), 2, "{errors}");
    assert_eq!(issues[0].source, Source::Dotenv(bad));
    assert!(
        issues[0].message.starts_with("line 2, column 5"),
        "{errors}"
    );
    assert_eq!(
        issues[1].source,
        Source::Dotenv(dir.path().join("needed.env"))
    );
}

#[test]
fn secret_values_stay_out_of_type_errors() {
    #[derive(Debug, Deserialize)]
    #[allow(dead_code)]
    struct S {
        api_token: u32,
    }
    let errors = ConfigLoader::new()
        .with_env(
            [("APP_API_TOKEN", "abc-secret-xyz")],
            &EnvMapping::new().prefix("APP_"),
        )
        .load()
        .unwrap()
        .deserialize::<S>()
        .unwrap_err();
    assert!(!errors.to_string().contains("abc-secret-xyz"), "{errors}");
}

#[test]
fn env_reader_over_dotenv_then_environment() {
    let dotenv = Dotenv::parse(
        "APP_HOST=dotenv\nAPP_PORT=1\nAPP_DEBUG=0\nAPP_DB__USER=u\nAPP_DB__PASSWORD=p\n",
    )
    .unwrap();
    let real = [("APP_PORT", "2")];
    let config: Config = EnvReader::new()
        .prefix("APP_")
        .from_vars(dotenv.vars().chain(real))
        .unwrap();
    assert_eq!((config.host.as_str(), config.port), ("dotenv", 2));
}

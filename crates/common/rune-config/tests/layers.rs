//! End-to-end loading: files, environment, CLI, typed errors.

#![allow(clippy::unwrap_used, reason = "test helpers")]

use std::path::PathBuf;

use rune_config::{CliOverrides, ConfigLoader, EnvMapping, Source, ValueKind};
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Config {
    #[serde(default)]
    name: String,
    scan: Scan,
    #[serde(default)]
    servers: Vec<Server>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Scan {
    rate_limit: u32,
    concurrency: u32,
    #[serde(default)]
    tags: Vec<String>,
}

impl Default for Scan {
    fn default() -> Self {
        Self {
            rate_limit: 5,
            concurrency: 8,
            tags: Vec::new(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Server {
    host: String,
    port: u16,
}

fn write(dir: &tempfile::TempDir, name: &str, text: &str) -> PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, text).unwrap();
    path
}

#[test]
fn full_stack_resolves_in_layer_order() {
    let dir = tempfile::tempdir().unwrap();
    let user = write(
        &dir,
        "user.toml",
        "name = \"user\"\n[scan]\nrate_limit = 6\nconcurrency = 6\n",
    );
    let project = write(
        &dir,
        "app.toml",
        "[scan]\nrate_limit = 7\n\n[[servers]]\nhost = \"a\"\nport = 1\n",
    );

    let loaded = ConfigLoader::new()
        .with_defaults_from(&Config::default())
        .with_user_file(Some(user.clone()))
        .with_project_file(&project, true)
        .with_env(
            [
                ("APP_SCAN__TAGS", "x"),
                ("APP_TAGS", "a, b"),
                ("UNRELATED", "1"),
            ],
            &EnvMapping::new().prefix("APP_").var_as(
                "APP_TAGS",
                "scan.tags",
                ValueKind::StringList,
            ),
        )
        .with_cli(&CliOverrides::new().set("--concurrency", "scan.concurrency", 1))
        .load()
        .unwrap();

    let config: Config = loaded.deserialize().unwrap();
    assert_eq!(config.name, "user");
    assert_eq!(config.scan.rate_limit, 7);
    assert_eq!(config.scan.concurrency, 1);
    assert_eq!(config.scan.tags, ["a", "b"]);
    assert_eq!(
        config.servers,
        [Server {
            host: "a".into(),
            port: 1
        }]
    );

    assert_eq!(loaded.source_of("name"), Some(&Source::UserFile(user)));
    assert_eq!(
        loaded.source_of("scan.rate_limit"),
        Some(&Source::ProjectFile(project.clone()))
    );
    assert_eq!(
        loaded.source_of("servers.host"),
        Some(&Source::ProjectFile(project))
    );
    assert_eq!(
        loaded.source_of("scan.tags"),
        Some(&Source::Env("APP_TAGS".into()))
    );
    assert_eq!(
        loaded.source_of("scan.concurrency"),
        Some(&Source::Cli("--concurrency".into()))
    );
    assert_eq!(loaded.sources().len(), 6);
}

#[test]
fn missing_files_skip_or_fail_by_requirement() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("nope.toml");
    let loaded = ConfigLoader::new()
        .with_user_file(Some(missing.clone()))
        .with_user_file(None)
        .load()
        .unwrap();
    assert_eq!(loaded.sources(), &[] as &[Source]);

    let errors = ConfigLoader::new()
        .with_project_file(&missing, true)
        .load()
        .unwrap_err();
    assert_eq!(errors.issues().len(), 1);
    assert_eq!(errors.issues()[0].source, Source::ProjectFile(missing));
    assert!(errors.to_string().contains("cannot read file"), "{errors}");
}

#[test]
fn every_layer_problem_is_reported_at_once() {
    let dir = tempfile::tempdir().unwrap();
    let user = write(&dir, "user.toml", "[scan\n");
    let errors = ConfigLoader::new()
        .with_user_file(Some(user.clone()))
        .with_env(
            [("APP_RPS", "fast")],
            &EnvMapping::new().var_as("APP_RPS", "scan.rate_limit", ValueKind::Integer),
        )
        .with_cli(&CliOverrides::new().assign("--set", "oops"))
        .load()
        .unwrap_err();
    let sources: Vec<_> = errors.iter().map(|i| i.source.clone()).collect();
    assert_eq!(
        sources,
        [
            Source::UserFile(user),
            Source::Env("APP_RPS".into()),
            Source::Cli("--set".into()),
        ]
    );
    let text = errors.to_string();
    assert!(
        text.starts_with("invalid configuration (3 problems):"),
        "{text}"
    );
    assert!(
        text.contains("environment variable APP_RPS: `scan.rate_limit`: expected an integer"),
        "{text}"
    );
}

fn type_error(loader: &ConfigLoader) -> rune_config::ConfigIssue {
    let errors = loader.load().unwrap().deserialize::<Config>().unwrap_err();
    assert_eq!(errors.issues().len(), 1, "{errors}");
    errors.into_issues().remove(0)
}

#[test]
fn type_errors_point_at_the_layer_that_set_the_key() {
    let base = || ConfigLoader::new().with_defaults_from(&Config::default());

    let issue =
        type_error(&base().with_cli(&CliOverrides::new().assign("--set", "scan.rate_limit=-3")));
    assert_eq!(issue.source, Source::Cli("--set".into()));
    assert_eq!(issue.key.as_deref(), Some("scan.rate_limit"));

    let issue = type_error(&base().with_env(
        [("APP_SCAN__CONCURRENCY", "many")],
        &EnvMapping::new().prefix("APP_"),
    ));
    assert_eq!(issue.source, Source::Env("APP_SCAN__CONCURRENCY".into()));
    assert_eq!(issue.key.as_deref(), Some("scan.concurrency"));

    let file = Source::Inline("project".into());
    let issue =
        type_error(&base().with_toml(file.clone(), "[[servers]]\nhost = \"a\"\nport = 70000\n"));
    assert_eq!(issue.source, file);
    assert_eq!(issue.key.as_deref(), Some("servers"));

    let issue = type_error(&base().with_toml(file.clone(), "[scan]\nunknown = 1\n"));
    assert_eq!(issue.source, file);
    assert_eq!(issue.key.as_deref(), Some("scan.unknown"));
    assert!(issue.message.contains("unknown"), "{}", issue.message);

    let issue = type_error(&base().with_toml(file.clone(), "scan = 5\n"));
    assert_eq!(issue.source, file);
    assert_eq!(issue.key.as_deref(), Some("scan"));

    let issue = type_error(&base().with_toml(file.clone(), "[scan.\"odd.key\"]\nx = 1\n"));
    assert_eq!(issue.source, file);
    assert_eq!(issue.key.as_deref(), Some("scan.\"odd.key\""));
}

#[test]
fn missing_required_values_name_the_table_and_its_layer() {
    let issue = type_error(
        &ConfigLoader::new().with_toml(Source::Inline("p".into()), "[scan]\nrate_limit = 1\n"),
    );
    assert_eq!(issue.source, Source::Inline("p".into()));
    assert_eq!(issue.key.as_deref(), Some("scan"));
    assert!(issue.message.contains("concurrency"), "{}", issue.message);

    let issue = type_error(
        &ConfigLoader::new()
            .with_toml(Source::Inline("p".into()), "[scan]\nrate_limit = 1\n")
            .with_toml(Source::Inline("q".into()), "[scan]\ntags = []\n"),
    );
    assert_eq!(issue.source, Source::Merged);
    assert_eq!(issue.key.as_deref(), Some("scan"));

    let issue =
        type_error(&ConfigLoader::new().with_toml(Source::Inline("p".into()), "name = \"x\""));
    assert_eq!(issue.source, Source::Merged);
    assert!(issue.message.contains("scan"), "{}", issue.message);
}

#[test]
fn defaults_that_are_not_tables_are_reported() {
    let errors = ConfigLoader::new()
        .with_defaults_from(&5_u8)
        .load()
        .unwrap_err();
    assert_eq!(errors.issues()[0].source, Source::Default);
}

#[test]
fn merged_config_round_trips_through_toml() {
    let loaded = ConfigLoader::new()
        .with_defaults_from(&Config::default())
        .with_toml(
            Source::Inline("p".into()),
            "name = \"x\"\n[[servers]]\nhost = \"h\"\nport = 2\n",
        )
        .load()
        .unwrap();
    let text = loaded.to_toml_string().unwrap();
    let reloaded = ConfigLoader::new()
        .with_toml(Source::Inline("again".into()), text)
        .load()
        .unwrap();
    assert_eq!(reloaded.table(), loaded.table());
    assert_eq!(
        reloaded.deserialize::<Config>().unwrap(),
        loaded.deserialize::<Config>().unwrap()
    );
}

#[test]
fn report_hides_secrets_nested_in_arrays() {
    let loaded = ConfigLoader::new()
        .with_defaults_toml(
            "[[upstreams]]\nhost = \"a.internal\"\npassword = \"hunter2\"\n\n\
             [scan]\nrate_limit = 5\n",
        )
        .load()
        .unwrap();
    let report = loaded.report().to_string();
    assert!(!report.contains("hunter2"), "{report}");
    assert!(report.contains("scan.rate_limit = 5"), "{report}");
    assert!(!format!("{loaded:?}").contains("hunter2"));
}

#[test]
fn type_errors_hide_secrets_nested_in_arrays() {
    #[derive(Debug, Deserialize)]
    #[allow(dead_code)]
    struct Upstream {
        host: String,
        password: u32,
    }
    #[derive(Debug, Deserialize)]
    #[allow(dead_code)]
    struct Upstreams {
        upstreams: Vec<Upstream>,
    }
    let loaded = ConfigLoader::new()
        .with_defaults_toml("[[upstreams]]\nhost = \"a\"\npassword = \"hunter2\"\n")
        .load()
        .unwrap();
    let error = loaded.deserialize::<Upstreams>().unwrap_err();
    assert!(!error.to_string().contains("hunter2"), "{error}");
}

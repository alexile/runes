//! `SecretRef` in a config struct loaded through rune-config layers.
#![cfg(feature = "serde")]

use rune_config::{CliOverrides, ConfigLoader, EnvMapping, Source, ValueKind};
use rune_secret_ref::{ResolveOptions, SecretRef, SecretValue};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Config {
    api: Api,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Api {
    token: SecretRef,
    #[serde(default)]
    fallback: Option<SecretRef>,
}

#[test]
fn every_layer_can_set_a_reference() {
    let project = Source::Inline("app.toml".into());
    let loaded = ConfigLoader::new()
        .with_toml(
            project.clone(),
            "[api]\ntoken = \"env:FROM_FILE\"\nfallback = { cmd = [\"pass\", \"show\", \"work/api token\"] }\n",
        )
        .load()
        .unwrap();
    let config: Config = loaded.deserialize().unwrap();
    assert_eq!(config.api.token, SecretRef::Env("FROM_FILE".into()));
    assert_eq!(
        config.api.fallback,
        Some(SecretRef::command(["pass", "show", "work/api token"]).unwrap())
    );

    let mapping = EnvMapping::new().var_as("APP_TOKEN", "api.token", ValueKind::String);
    let loaded = ConfigLoader::new()
        .with_toml(project.clone(), "[api]\ntoken = \"env:FROM_FILE\"\n")
        .with_env([("APP_TOKEN", "file:/run/secrets/token")], &mapping)
        .load()
        .unwrap();
    let config: Config = loaded.deserialize().unwrap();
    assert_eq!(
        config.api.token,
        SecretRef::File("/run/secrets/token".into())
    );

    let loaded = ConfigLoader::new()
        .with_toml(project, "[api]\ntoken = \"env:FROM_FILE\"\n")
        .with_cli(&CliOverrides::new().set_opt(
            "--token",
            "api.token",
            Some("cmd:op read op://x/y"),
        ))
        .load()
        .unwrap();
    let config: Config = loaded.deserialize().unwrap();
    assert_eq!(
        config.api.token,
        SecretRef::command(["op", "read", "op://x/y"]).unwrap()
    );
    assert_eq!(
        loaded.source_of("api.token"),
        Some(&Source::Cli("--token".into()))
    );

    let token = SecretRef::Env("FROM_FILE".into())
        .resolve(&ResolveOptions::default(), |_| Some("v".into()))
        .unwrap();
    assert_eq!(token, SecretValue::new("v"));
}

#[test]
fn inline_secret_is_reported_against_its_layer_without_the_value() {
    const SECRET: &str = "sk-live-0123456789abcdef";
    let project = Source::Inline("app.toml".into());
    for value in [
        format!("\"{SECRET}\""),
        format!("{{ env = \"{SECRET}\" }}"),
        format!("{{ \"{SECRET}\" = \"x\" }}"),
        "123456789".to_owned(),
        "[\"a\"]".to_owned(),
    ] {
        let errors = ConfigLoader::new()
            .with_toml(project.clone(), format!("[api]\ntoken = {value}\n"))
            .load()
            .unwrap()
            .deserialize::<Config>()
            .unwrap_err();
        let issue = &errors.issues()[0];
        assert_eq!(issue.source, project, "{value}");
        assert_eq!(issue.key.as_deref(), Some("api.token"), "{value}");
        let report = format!("{errors} {errors:?}");
        assert!(!report.contains(SECRET), "{report}");
        assert!(!report.contains("123456789"), "{report}");
    }
}

#[test]
fn serializes_back_to_the_same_layer_input() {
    for text in [
        "env:A",
        "file:/x y",
        "cmd:pass show k",
        "keychain:s/a",
        "vault:p",
    ] {
        let reference: SecretRef = text.parse().unwrap();
        let value = toml::Value::try_from(&reference).unwrap();
        assert_eq!(value.as_str(), Some(text));
        assert_eq!(value.try_into::<SecretRef>().unwrap(), reference);
    }
    let spaced = SecretRef::command(["pass", "show", "a b"]).unwrap();
    let value = toml::Value::try_from(&spaced).unwrap();
    assert!(value.is_table());
    assert_eq!(value.try_into::<SecretRef>().unwrap(), spaced);
}

#[test]
fn table_form_rejects_ambiguity() {
    for body in [
        "{}",
        "{ env = \"A\", file = \"/b\" }",
        "{ file = [\"/a\"] }",
        "{ cmd = [] }",
        "{ cmd = [1] }",
    ] {
        let result = toml::from_str::<Api>(&format!("token = {body}\n"));
        assert!(result.is_err(), "{body}");
    }
}

#[test]
fn secret_value_serializes_redacted() {
    #[derive(Serialize)]
    struct Resolved {
        token: SecretValue,
    }
    let text = toml::to_string(&Resolved {
        token: SecretValue::new("hunter2"),
    })
    .unwrap();
    assert_eq!(text.trim(), "token = \"<redacted>\"");
}

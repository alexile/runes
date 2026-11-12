# rune-notify

> Notification sinks for findings and alerts: Slack, Discord, generic JSON webhook and Jira, over a caller-supplied HTTP transport

[![crates.io](https://img.shields.io/crates/v/rune-notify)](https://crates.io/crates/rune-notify)
[![docs.rs](https://img.shields.io/docsrs/rune-notify)](https://docs.rs/rune-notify)
[![license](https://img.shields.io/crates/l/rune-notify)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

Routes alerts and [`rune-finding`](../../secops/rune-finding) findings to
Slack, Discord, a generic JSON webhook or Jira.

- **Sans-I/O sinks.** Each sink builds the provider's HTTP request and reads
  its response. The crate ships no HTTP client: implement the one-method
  `Transport` trait over the client you already use (a closure works), or
  call `Sink::request` / `Sink::response` around an async client.
- **Provider-correct payloads.** Slack [Block Kit] via incoming webhooks,
  Discord [execute-webhook] embeds, Jira [REST v2 create-issue], and a
  stable, versioned JSON shape for generic webhooks. Text is escaped for each
  provider's markup (no `<!channel>` or `@everyone` injection from finding
  data) and cut to each provider's length limits.
- **Secrets stay secret.** Webhook URLs, API tokens and auth headers are
  `rune-secret-ref` `SecretValue`s, redacted from `Debug` and never put in
  errors.
- **Templates.** `{placeholder}` templates render a `Finding` into a
  provider-neutral `Message`.
- **Retries.** `Notifier` fans out to several sinks with per-route severity
  filters and retries throttled (429), failed (5xx) and unreachable
  deliveries on a `rune-retry-queue` backoff, dead-lettering what never gets
  through. Permanent rejections (bad token, bad payload) are not retried.

[Block Kit]: https://api.slack.com/reference/block-kit/blocks
[execute-webhook]: https://discord.com/developers/docs/resources/webhook#execute-webhook
[REST v2 create-issue]: https://developer.atlassian.com/cloud/jira/platform/rest/v2/api-group-issues/#api-rest-api-2-issue-post

## Installation

```toml
[dependencies]
rune-notify = "0.1"
```

## Usage

```rust
use std::time::{Duration, Instant};

use rune_finding::{Confidence, Finding, Location, Severity};
use rune_notify::{
    HttpRequest, HttpResponse, JiraAuth, JiraSink, Message, MessageTemplate, Notifier,
    SlackSink, Template, TransportError,
};
use rune_retry_queue::BackoffPolicy;
use rune_secret_ref::SecretValue;

fn main() -> Result<(), rune_notify::Error> {
    // Secrets normally come from `SecretRef::resolve` (env:, file:, cmd:).
    let slack = SlackSink::new(SecretValue::new("https://hooks.slack.com/services/T0/B0/XXXX"))?;
    let jira = JiraSink::new(
        "https://acme.atlassian.net",
        "SEC",
        JiraAuth::basic("bot@acme.test", SecretValue::new("api-token")),
    )?;

    let mut notifier = Notifier::new(BackoffPolicy::Fixed(Duration::from_secs(30)), 5);
    notifier.add(slack);
    notifier.add_route(jira, Severity::High); // only High and Critical open tickets

    let finding = Finding::<()>::new(
        "python.sqli",
        "SQL built with string formatting",
        Severity::High,
        Confidence::Firm,
        Location::file("src/app.py").with_lines(42, 42),
    );
    let message = MessageTemplate::default()
        .with_title(Template::parse("{severity_upper}: {title} ({location})")?)
        .render(&finding);

    // Wrap your HTTP client here; this stand-in answers like each provider.
    let transport = |request: &HttpRequest| -> Result<HttpResponse, TransportError> {
        if request.url.expose().contains("atlassian") {
            Ok(HttpResponse::new(201).with_body(r#"{"id":"1","key":"SEC-1","self":"x"}"#))
        } else {
            Ok(HttpResponse::new(200).with_body("ok"))
        }
    };

    let now = Instant::now();
    for outcome in notifier.notify(&message, &transport, now) {
        println!("{} -> {:?}", outcome.sink, outcome.status);
    }
    // Call periodically to retry throttled or failed deliveries.
    notifier.retry_due(&transport, now);
    for dead in notifier.drain_dead_letters() {
        eprintln!("gave up on {:?}: {}", dead.route, dead.error);
    }
    Ok(())
}
```

### Template placeholders

`{title}`, `{check_id}`, `{severity}`, `{severity_upper}`, `{confidence}`,
`{location}`, `{fingerprint}`, `{fingerprint_short}`, `{cwe}`, `{taxonomy}`,
`{remediation}`, `{references}`, `{cvss}`, `{cvss_score}`, `{evidence}`.
`{{` and `}}` are literal braces; unknown placeholders fail at parse time.

### Writing a transport

A transport should apply a timeout, **not follow redirects** (that would
forward the payload, and possibly credentials, to a host you did not
configure), and keep the URL and headers out of its error messages.
Return `TransportError::retryable` for connection failures and timeouts.

## License

MIT

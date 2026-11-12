//! Property tests: arbitrary text never panics and never breaks provider
//! limits.

use proptest::prelude::*;
use rune_finding::{Confidence, Finding, Location, Severity};
use rune_notify::{
    DiscordSink, Field, JiraAuth, JiraSink, Message, Sink, SlackSink, Template, WebhookSink,
};
use rune_secret_ref::SecretValue;
use serde_json::Value;

fn chars(v: &Value) -> usize {
    v.as_str().map_or(0, |s| s.chars().count())
}

fn message() -> impl Strategy<Value = Message> {
    (
        ".{0,400}",
        ".{0,7000}",
        proptest::collection::vec((".{0,300}", ".{0,1500}"), 0..30),
        proptest::option::of(".{0,200}"),
    )
        .prop_map(|(title, body, fields, link)| {
            let mut m = Message::new(title, body).with_severity(Severity::Medium);
            for (name, value) in fields {
                m = m.push_field(Field::new(name, value));
            }
            if let Some(link) = link {
                m = m.with_link(link);
            }
            m
        })
}

proptest! {
    #[test]
    fn template_parse_never_panics(text in ".{0,200}") {
        if let Ok(template) = Template::parse(&text) {
            let finding = Finding::<()>::new("c", "t", Severity::Low, Confidence::Firm, Location::file("f"));
            let _ = template.render(&finding);
        }
    }

    #[test]
    fn literal_text_round_trips(text in "[^{}]{0,200}") {
        let finding = Finding::<()>::new("c", "t", Severity::Low, Confidence::Firm, Location::file("f"));
        prop_assert_eq!(Template::parse(&text).map(|t| t.render(&finding)), Ok(text));
    }

    #[test]
    fn slack_respects_block_kit_limits(m in message()) {
        let sink = SlackSink::new(SecretValue::new("https://hooks.test/x")).unwrap();
        let p = sink.payload(&m);
        prop_assert!(chars(&p["blocks"][0]["text"]["text"]) <= 150);
        for block in p["blocks"].as_array().unwrap() {
            prop_assert!(chars(&block["text"]["text"]) <= 3000);
            let fields = block["fields"].as_array().cloned().unwrap_or_default();
            prop_assert!(fields.len() <= 10);
            for f in fields {
                prop_assert!(chars(&f["text"]) <= 2000);
            }
        }
        prop_assert!(sink.request(&m).is_ok());
    }

    #[test]
    fn discord_respects_embed_limits(m in message()) {
        let sink = DiscordSink::new(SecretValue::new("https://discord.test/api/webhooks/1/x")).unwrap();
        let e = &sink.payload(&m)["embeds"][0];
        let fields = e["fields"].as_array().cloned().unwrap_or_default();
        prop_assert!(fields.len() <= 25);
        prop_assert!(chars(&e["title"]) <= 256);
        prop_assert!(chars(&e["description"]) <= 4096);
        let mut total = chars(&e["title"]) + chars(&e["description"]) + chars(&e["footer"]["text"]);
        for f in &fields {
            prop_assert!(chars(&f["name"]) <= 256 && chars(&f["name"]) > 0);
            prop_assert!(chars(&f["value"]) <= 1024 && chars(&f["value"]) > 0);
            total += chars(&f["name"]) + chars(&f["value"]);
        }
        prop_assert!(total <= 6000);
    }

    #[test]
    fn jira_and_webhook_build(m in message()) {
        let jira = JiraSink::new("https://j.test", "SEC", JiraAuth::Bearer(SecretValue::new("t"))).unwrap();
        let p = jira.payload(&m);
        prop_assert!(chars(&p["fields"]["summary"]) <= 255);
        prop_assert!(!p["fields"]["summary"].as_str().unwrap_or("\n").contains('\n'));
        prop_assert!(jira.request(&m).is_ok());
        let hook = WebhookSink::new(SecretValue::new("https://h.test/")).unwrap();
        prop_assert!(hook.request(&m).is_ok());
    }
}

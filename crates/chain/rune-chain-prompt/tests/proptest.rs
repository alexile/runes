//! Property tests for template rendering: escapes round-trip, substituted
//! values are never re-interpreted, `input_variables` names exactly what
//! `format` needs, and no input makes either panic.

#![allow(clippy::unwrap_used, reason = "test assertions")]

use proptest::prelude::*;
use rune_chain_core::Message;
use rune_chain_core::{ChainError, PromptArgs};
use rune_chain_prompt::{
    ChatTemplate, MessageTemplate, MessagesPlaceholder, PromptTemplate, StringTemplate,
    TemplateError, ValueGuard, escape_xml, messages_value, strip_invisible,
};
use serde_json::Value;

/// Escape literal text so the template renders it verbatim.
fn escape(text: &str) -> String {
    text.replace('{', "{{").replace('}', "}}")
}

#[derive(Debug, Clone)]
enum Part {
    Text(String),
    Var(String),
}

fn part() -> impl Strategy<Value = Part> {
    prop_oneof![
        any::<String>().prop_map(Part::Text),
        "[a-z][a-z0-9_]{0,6}".prop_map(Part::Var),
    ]
}

proptest! {
    #[test]
    fn rendering_never_panics(template in any::<String>(), value in any::<String>()) {
        let t = StringTemplate::new(template);
        let vars = t.input_variables();
        let _ = t.format(&PromptArgs::new());
        let args: PromptArgs = vars.iter().map(|v| (v.clone(), Value::String(value.clone()))).collect();
        let _ = t.format(&args);
    }

    #[test]
    fn supplying_every_input_variable_is_enough(template in any::<String>()) {
        let t = StringTemplate::new(template);
        let args: PromptArgs = t
            .input_variables()
            .into_iter()
            .map(|v| (v, Value::String("x".into())))
            .collect();
        prop_assert!(t.format(&args).is_ok(), "{:?}", t.format(&args));
    }

    #[test]
    fn escaped_text_renders_verbatim(text in any::<String>()) {
        let t = StringTemplate::new(escape(&text));
        prop_assert!(t.input_variables().is_empty());
        prop_assert_eq!(t.format(&PromptArgs::new()).unwrap(), text);
    }

    #[test]
    fn values_are_inserted_verbatim(value in any::<String>()) {
        // Braces inside a value must not be treated as template syntax.
        let t = StringTemplate::new("<{v}>");
        let args = PromptArgs::from([("v".to_string(), Value::String(value.clone()))]);
        prop_assert_eq!(t.format(&args).unwrap(), format!("<{value}>"));
    }

    #[test]
    fn composed_templates_render_as_expected(parts in prop::collection::vec(part(), 0..8)) {
        let mut template = String::new();
        let mut expected = String::new();
        let mut vars: Vec<String> = Vec::new();
        for p in &parts {
            match p {
                Part::Text(t) => {
                    template.push_str(&escape(t));
                    expected.push_str(t);
                }
                Part::Var(v) => {
                    template.push('{');
                    template.push_str(v);
                    template.push('}');
                    expected.push_str(&v.to_uppercase());
                    if !vars.contains(v) {
                        vars.push(v.clone());
                    }
                }
            }
        }
        let t = StringTemplate::new(template);
        prop_assert_eq!(t.input_variables(), vars.clone());
        let args: PromptArgs = vars.iter().map(|v| (v.clone(), Value::String(v.to_uppercase()))).collect();
        prop_assert_eq!(t.format(&args).unwrap(), expected);

        // Dropping any one variable is reported by name.
        if let Some(missing) = vars.first() {
            let mut partial = args;
            partial.remove(missing);
            match t.format(&partial) {
                Err(ChainError::MissingVariable(name)) => prop_assert_eq!(&name, missing),
                other => prop_assert!(false, "expected MissingVariable, got {:?}", other),
            }
        }
    }

    #[test]
    fn strict_and_lenient_agree_on_valid_templates(template in any::<String>()) {
        // Whenever strict parsing accepts a template it must mean exactly
        // what the lenient parser makes of it.
        if let Ok(strict) = StringTemplate::try_new(template.clone()) {
            let lenient = StringTemplate::new(template);
            prop_assert_eq!(strict.input_variables(), lenient.input_variables());
            let args: PromptArgs = lenient
                .input_variables()
                .into_iter()
                .map(|v| (v.clone(), Value::String(v)))
                .collect();
            prop_assert_eq!(strict.format(&args).unwrap(), lenient.format(&args).unwrap());
        }
    }

    #[test]
    fn strict_accepts_escaped_text(text in any::<String>()) {
        prop_assert!(StringTemplate::try_new(escape(&text)).is_ok());
    }

    #[test]
    fn try_format_lists_exactly_the_missing(template in any::<String>(), keep in any::<u64>()) {
        let t = StringTemplate::new(template);
        let vars = t.input_variables();
        let args: PromptArgs = vars
            .iter()
            .enumerate()
            .filter(|(i, _)| keep >> (i % 64) & 1 == 1)
            .map(|(_, v)| (v.clone(), Value::from(1)))
            .collect();
        let expected: Vec<String> = vars.into_iter().filter(|v| !args.contains_key(v)).collect();
        match t.try_format(&args) {
            Ok(_) => prop_assert!(expected.is_empty()),
            Err(TemplateError::MissingVariables(m)) => prop_assert_eq!(m, expected),
            Err(other) => prop_assert!(false, "unexpected {:?}", other),
        }
    }

    #[test]
    fn xml_tag_guard_cannot_be_escaped(value in any::<String>()) {
        let t = StringTemplate::new("{v}").guard("v", ValueGuard::untrusted("data"));
        let out = t.format(&PromptArgs::from([("v".to_string(), Value::String(value))])).unwrap();
        let inner = out.strip_prefix("<data>").and_then(|s| s.strip_suffix("</data>")).unwrap();
        prop_assert!(!inner.contains('<') && !inner.contains('>'));
    }

    #[test]
    fn escape_xml_has_no_raw_specials(value in any::<String>()) {
        let e = escape_xml(&value);
        prop_assert!(!e.contains(['<', '>', '"', '\'']));
    }

    #[test]
    fn strip_invisible_is_idempotent(value in any::<String>()) {
        let once = strip_invisible(&value);
        prop_assert_eq!(&strip_invisible(&once), &once);
        prop_assert!(once.chars().all(|c| !c.is_control() || c == '\n' || c == '\t'));
    }

    #[test]
    fn max_len_is_enforced(value in any::<String>(), max in 0usize..64) {
        let t = StringTemplate::new("x{v}").with_max_len(max);
        let args = PromptArgs::from([("v".to_string(), Value::String(value.clone()))]);
        match t.try_format(&args) {
            Ok(out) => prop_assert!(out.len() <= max),
            Err(TemplateError::TooLong { len, .. }) => prop_assert_eq!(len, value.len() + 1),
            Err(other) => prop_assert!(false, "unexpected {:?}", other),
        }
    }

    #[test]
    fn placeholder_round_trips_history(texts in prop::collection::vec(any::<String>(), 0..6), last in 0usize..8) {
        let history: Vec<Message> = texts.iter().map(Message::human).collect();
        let t = ChatTemplate::new(vec![]).with_placeholder(MessagesPlaceholder::new("h").last(last));
        let args = PromptArgs::from([("h".to_string(), messages_value(&history))]);
        let out = t.format_messages(&args).unwrap();
        let skip = history.len().saturating_sub(last);
        prop_assert_eq!(out, history[skip..].to_vec());
    }

    #[test]
    fn placeholder_never_panics_on_arbitrary_json(s in any::<String>(), n in any::<i64>()) {
        let t = ChatTemplate::new(vec![]).with_placeholder(MessagesPlaceholder::new("h"));
        for v in [Value::String(s.clone()), Value::from(n), serde_json::json!([s, n]), serde_json::json!([{"role": s, "content": n}])] {
            let _ = t.format_messages(&PromptArgs::from([("h".to_string(), v)]));
        }
    }

    #[test]
    fn chat_templates_agree_with_their_messages(a in "[a-z]{1,5}", b in "[a-z]{1,5}") {
        let chat = ChatTemplate::new(vec![
            MessageTemplate::system(format!("{{{a}}}")),
            MessageTemplate::human(format!("{{{b}}} and {{{a}}}")),
        ]);
        let mut expected = vec![a.clone()];
        if b != a {
            expected.push(b.clone());
        }
        prop_assert_eq!(chat.input_variables(), expected);
        let args = PromptArgs::from([(a, Value::from(1)), (b, Value::from(2))]);
        let msgs = chat.format_messages(&args).unwrap();
        prop_assert_eq!(msgs.len(), 2);
    }
}

#[test]
fn non_string_values_render_as_json() {
    let t = StringTemplate::new("{n} {b} {o} {s}");
    let args: PromptArgs = [
        ("n".to_string(), Value::from(1.5)),
        ("b".to_string(), Value::from(true)),
        ("o".to_string(), serde_json::json!({"k": [1]})),
        ("s".to_string(), Value::from("plain")),
    ]
    .into_iter()
    .collect();
    assert_eq!(t.format(&args).unwrap(), r#"1.5 true {"k":[1]} plain"#);
}

#[test]
fn empty_braces_are_literal() {
    // `{}` names no variable, so it renders as written (JSON examples in
    // prompts stay intact) and is not listed as an input variable.
    let t = StringTemplate::new("Reply with {} or {x}.");
    assert_eq!(t.input_variables(), ["x"]);
    let args = PromptArgs::from([("x".to_string(), Value::from("[]"))]);
    assert_eq!(t.format(&args).unwrap(), "Reply with {} or [].");
}

#[test]
fn unterminated_placeholder_names_its_variable() {
    let t = StringTemplate::new("Hello {name");
    assert_eq!(t.input_variables(), ["name"]);
    let args = PromptArgs::from([("name".to_string(), Value::from("Ada"))]);
    assert_eq!(t.format(&args).unwrap(), "Hello Ada");
    assert!(
        StringTemplate::new("trailing {")
            .format(&PromptArgs::new())
            .is_ok()
    );
}

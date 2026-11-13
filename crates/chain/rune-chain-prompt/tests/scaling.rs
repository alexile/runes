//! Work on long templates must grow roughly linearly with their size.

#![allow(clippy::unwrap_used, reason = "test assertions")]

use std::fmt::Write as _;
use std::time::{Duration, Instant};

use rune_chain_core::PromptArgs;
use rune_chain_prompt::{ChatTemplate, MessageTemplate, PromptTemplate, StringTemplate};

fn many_vars(n: usize) -> (String, PromptArgs) {
    let mut template = String::new();
    let mut args = PromptArgs::new();
    for i in 0..n {
        let _ = write!(template, "{{v{i}}}");
        args.insert(format!("v{i}"), "x".into());
    }
    (template, args)
}

#[test]
fn many_distinct_variables_format_quickly() {
    // About 1 MB of template text. Deduplicating variable names pairwise
    // turned this into billions of string comparisons per call.
    let (template, args) = many_vars(100_000);
    let started = Instant::now();
    let tmpl = StringTemplate::try_new(template.clone()).unwrap();
    assert_eq!(tmpl.input_variables().len(), 100_000);
    assert_eq!(tmpl.format(&args).unwrap().len(), 100_000);
    let declared: Vec<String> = args.keys().cloned().collect();
    tmpl.validate_input_variables(&declared).unwrap();

    let chat = ChatTemplate::new(vec![MessageTemplate::human(template)]);
    assert_eq!(chat.input_variables().len(), 100_000);
    assert_eq!(chat.missing_variables(&args), Vec::<String>::new());
    chat.validate_input_variables(&declared).unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "took {:?}",
        started.elapsed()
    );
}

//! `prompt_args!` must expand cleanly in caller code, with or without
//! arguments, under strict lints.

#![deny(unused_mut)]

use rune_chain_core::{PromptArgs, prompt_args};

#[test]
fn empty_invocation_compiles_without_unused_mut() {
    let braces: PromptArgs = prompt_args! {};
    let parens: PromptArgs = prompt_args!();
    let comma: PromptArgs = prompt_args! {,};
    assert!(braces.is_empty() && parens.is_empty() && comma.is_empty());
}

#[test]
fn pairs_are_collected_and_last_duplicate_wins() {
    let args = prompt_args! {
        "name" => "Alice",
        "n" => 1,
        "n" => [1, 2],
    };
    assert_eq!(args.len(), 2);
    assert_eq!(args["name"], "Alice");
    assert_eq!(args["n"], serde_json::json!([1, 2]));
}

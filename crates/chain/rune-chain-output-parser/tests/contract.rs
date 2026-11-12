//! `ParsedChain` against the shared `Chain` contract: parsing success keeps
//! the inner usage, and unparseable output is an error on every entry point.

#![allow(clippy::unwrap_used, reason = "test assertions")]

use async_trait::async_trait;
use rune_chain_core::testing::{check_chain, check_chain_rejects};
use rune_chain_core::{Chain, ChainError, GenerateResult, PromptArgs, TokenUsage, prompt_args};
use rune_chain_output_parser::{BoolOutputParser, ListOutputParser, ParsedChain};

/// Replies with the `input` variable verbatim, reporting fixed usage.
struct Reply;

#[async_trait]
impl Chain for Reply {
    async fn call(&self, input: PromptArgs) -> Result<GenerateResult, ChainError> {
        let text = input
            .get("input")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ChainError::MissingVariable("input".into()))?;
        let mut r = GenerateResult::from_text(text);
        r.tokens = Some(TokenUsage::new(2, 3).with_total_tokens(5));
        Ok(r)
    }

    fn input_keys(&self) -> Vec<String> {
        vec!["input".into()]
    }
}

#[tokio::test]
async fn meets_the_chain_contract_when_output_parses() {
    let chain = ParsedChain::new(Reply, BoolOutputParser);
    check_chain(&chain, &prompt_args! { "input" => "Yes" })
        .await
        .unwrap();
    let r = chain.call(prompt_args! { "input" => "no" }).await.unwrap();
    assert_eq!(r.generation, "false");
    assert_eq!(r.tokens.unwrap().total_tokens, 5);
    assert!(!chain.parse(prompt_args! { "input" => "NO" }).await.unwrap());
    assert_eq!(chain.input_keys(), ["input"]);
}

#[tokio::test]
async fn unparseable_output_is_rejected() {
    let chain = ParsedChain::new(Reply, BoolOutputParser);
    check_chain_rejects(&chain, &prompt_args! { "input" => "perhaps" })
        .await
        .unwrap();
    check_chain_rejects(&chain, &prompt_args! {}).await.unwrap();
}

#[tokio::test]
async fn list_output_is_rendered_with_debug_formatting() {
    let chain = ParsedChain::new(Reply, ListOutputParser::new());
    let out = chain
        .invoke(prompt_args! { "input" => "a\nb" })
        .await
        .unwrap();
    assert_eq!(out, r#"["a", "b"]"#);
}

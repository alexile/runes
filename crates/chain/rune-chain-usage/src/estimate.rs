//! Local token estimates, for pre-flight budget checks and for calls whose
//! provider reports no usage (streams).
//!
//! Text is counted with [`rune_tokenize::estimate`] (about four characters
//! per token, rounded up), plus a small fixed overhead per message for the
//! role and framing tokens chat formats add. Expect estimates within roughly
//! ±30 % of provider counts for English prose; they are a guard rail, not an
//! invoice. Provider-reported usage always takes precedence when present.

use rune_chain_core::{FunctionDefinition, Message, ToolCall};

/// Framing tokens charged per message (role markers, separators).
pub const TOKENS_PER_MESSAGE: u64 = 4;
/// Tokens that prime the assistant's reply.
pub const TOKENS_PER_REPLY: u64 = 3;

/// Estimated tokens in `text`.
///
/// ```rust
/// assert_eq!(rune_chain_usage::estimate_text("hello world"), 3);
/// ```
#[must_use]
pub fn estimate_text(text: &str) -> u64 {
    rune_tokenize::estimate(text) as u64
}

fn estimate_calls(calls: &[ToolCall]) -> u64 {
    calls
        .iter()
        .map(|c| estimate_text(&c.name).saturating_add(estimate_text(&c.arguments)))
        .fold(0, u64::saturating_add)
}

/// Estimated prompt tokens for a conversation.
///
/// ```rust
/// use rune_chain_core::Message;
/// use rune_chain_usage::estimate_messages;
///
/// let n = estimate_messages(&[Message::system("Be terse."), Message::human("Capital of France?")]);
/// assert_eq!(n, (4 + 3) + (4 + 5) + 3);
/// ```
#[must_use]
pub fn estimate_messages(messages: &[Message]) -> u64 {
    messages
        .iter()
        .map(|m| {
            TOKENS_PER_MESSAGE
                .saturating_add(estimate_text(&m.content.text_content()))
                .saturating_add(estimate_calls(&m.tool_calls))
        })
        .fold(TOKENS_PER_REPLY, u64::saturating_add)
}

/// Estimated prompt tokens taken by tool definitions.
#[must_use]
pub fn estimate_tools(tools: &[FunctionDefinition]) -> u64 {
    tools
        .iter()
        .map(|t| {
            estimate_text(&t.name)
                .saturating_add(estimate_text(&t.description))
                .saturating_add(estimate_text(&t.parameters.to_string()))
        })
        .fold(0, u64::saturating_add)
}

/// Estimated completion tokens for a reply with `text` and `tool_calls`.
#[must_use]
pub fn estimate_reply(text: &str, tool_calls: &[ToolCall]) -> u64 {
    estimate_text(text).saturating_add(estimate_calls(tool_calls))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_conversation_costs_reply_priming() {
        assert_eq!(estimate_messages(&[]), TOKENS_PER_REPLY);
        assert_eq!(estimate_text(""), 0);
        assert_eq!(estimate_tools(&[]), 0);
    }

    #[test]
    fn tool_calls_and_definitions_count() {
        let call = ToolCall::new("id", "add", r#"{"a":1,"b":2}"#);
        assert_eq!(estimate_reply("", std::slice::from_ref(&call)), 1 + 4);
        let m = Message::ai_with_tool_calls("", vec![call]);
        assert_eq!(
            estimate_messages(&[m]),
            TOKENS_PER_REPLY + TOKENS_PER_MESSAGE + 5
        );
        let def = FunctionDefinition::single_input("upper", "Upper-cases text.");
        assert!(estimate_tools(&[def]) > 5);
    }

    #[test]
    fn multibyte_text_counts_characters() {
        assert_eq!(estimate_text("日本語テキスト"), 2);
    }
}

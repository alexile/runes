//! Cheap prompt-size estimate for routing decisions.

use rune_chain_core::Message;

/// Tokens charged per image by [`estimate_tokens`]: a mid-size image on
/// current vision models.
pub const IMAGE_TOKEN_ESTIMATE: usize = 1_000;

/// Rough token count of `messages`: about four characters per token, plus
/// a few tokens of per-message framing, tool-call arguments and
/// [`IMAGE_TOKEN_ESTIMATE`] per image.
///
/// It errs on the high side for English and is only meant for routing
/// (context-window filtering, price comparison). Use
/// [`Router::token_estimator`](crate::Router::token_estimator) to plug in a
/// real tokenizer.
///
/// # Example
///
/// ```rust
/// use rune_chain_core::Message;
/// use rune_chain_retry::estimate_tokens;
///
/// let n = estimate_tokens(&[Message::human("a".repeat(400))]);
/// assert!((100..=110).contains(&n));
/// ```
#[must_use]
pub fn estimate_tokens(messages: &[Message]) -> usize {
    messages
        .iter()
        .map(|m| {
            let chars = m.content.text_content().chars().count()
                + m.tool_calls
                    .iter()
                    .map(|c| c.name.len() + c.arguments.len())
                    .sum::<usize>();
            4 + chars.div_ceil(4) + m.content.images().count() * IMAGE_TOKEN_ESTIMATE
        })
        .fold(0, usize::saturating_add)
}

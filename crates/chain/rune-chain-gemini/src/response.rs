//! Provider-level view of a `generateContent` response.

use rune_chain_core::{
    FinishReason, GenerateResult, LlmError, ReasoningBlock, TokenUsage, ToolCall,
};
use serde_json::Value;

use crate::types::{
    GenerateContentResponse, Part, PromptFeedback, SafetyRatingWire, UsageMetadata,
};

/// Prefix of the call ids this crate makes up for function calls the API
/// sent without one. Such ids are not sent back to the API.
pub const SYNTHETIC_CALL_ID_PREFIX: &str = "gemini_call_";

/// Token usage as reported in `usageMetadata`.
///
/// `prompt_tokens` includes cached tokens; output is split into visible
/// candidates and thinking. [`to_token_usage`](Self::to_token_usage) maps
/// it onto the portable [`TokenUsage`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Usage {
    /// `promptTokenCount`: the whole prompt, cached part included.
    pub prompt_tokens: u32,
    /// `candidatesTokenCount`: visible output.
    pub candidates_tokens: u32,
    /// `thoughtsTokenCount`: thinking output.
    pub thoughts_tokens: u32,
    /// `cachedContentTokenCount`: prompt tokens served from the cache.
    pub cached_tokens: u32,
    /// `toolUsePromptTokenCount`: input of built-in tool calls.
    pub tool_use_prompt_tokens: u32,
    /// `totalTokenCount`, when reported. The portable usage recomputes the
    /// total from its parts instead.
    pub total_tokens: Option<u32>,
}

impl Usage {
    pub(crate) fn from_wire(u: &UsageMetadata) -> Self {
        Self {
            prompt_tokens: u.prompt_token_count.unwrap_or(0),
            candidates_tokens: u.candidates_token_count.unwrap_or(0),
            thoughts_tokens: u.thoughts_token_count.unwrap_or(0),
            cached_tokens: u.cached_content_token_count.unwrap_or(0),
            tool_use_prompt_tokens: u.tool_use_prompt_token_count.unwrap_or(0),
            total_tokens: u.total_token_count,
        }
    }

    /// The portable [`TokenUsage`]: prompt is prompt plus tool-use prompt
    /// tokens, completion is visible output plus thinking, with the cached
    /// and thinking shares broken out (all saturating).
    #[must_use]
    pub const fn to_token_usage(&self) -> TokenUsage {
        let prompt = self
            .prompt_tokens
            .saturating_add(self.tool_use_prompt_tokens);
        let completion = self.candidates_tokens.saturating_add(self.thoughts_tokens);
        TokenUsage::new(prompt, completion)
            .with_cache_read_tokens(if self.cached_tokens < prompt {
                self.cached_tokens
            } else {
                prompt
            })
            .with_reasoning_tokens(if self.thoughts_tokens < completion {
                self.thoughts_tokens
            } else {
                completion
            })
    }
}

/// A safety rating of a candidate or the prompt.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct SafetyRating {
    /// `HARM_CATEGORY_…`.
    pub category: String,
    /// `NEGLIGIBLE`, `LOW`, `MEDIUM` or `HIGH`.
    pub probability: String,
    /// Whether this rating caused a block.
    pub blocked: bool,
}

impl From<SafetyRatingWire> for SafetyRating {
    fn from(r: SafetyRatingWire) -> Self {
        Self {
            category: r.category,
            probability: r.probability,
            blocked: r.blocked,
        }
    }
}

/// One part of the response content.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum ResponsePart {
    /// Visible text.
    Text {
        /// The text.
        text: String,
        /// `thoughtSignature`, if the API attached one.
        signature: Option<String>,
    },
    /// A thought summary (only with `includeThoughts`).
    Thought {
        /// The summary text.
        text: String,
        /// `thoughtSignature`, if the API attached one.
        signature: Option<String>,
    },
    /// A function call.
    FunctionCall {
        /// The API's call id, or a made-up one starting with
        /// [`SYNTHETIC_CALL_ID_PREFIX`].
        id: String,
        /// Function name.
        name: String,
        /// Arguments (a JSON object).
        args: Value,
        /// `thoughtSignature`, if the API attached one.
        signature: Option<String>,
    },
}

/// A complete `generateContent` response with everything the portable
/// [`GenerateResult`] cannot carry: thought summaries and signatures, the
/// raw finish reason, safety ratings and the full usage breakdown.
///
/// Returned by [`Gemini::generate_content`](crate::Gemini::generate_content)
/// and at the end of [`Gemini::stream_content`](crate::Gemini::stream_content).
#[derive(Debug, Clone, Default, PartialEq)]
#[non_exhaustive]
pub struct GeminiResponse {
    /// `responseId`.
    pub response_id: String,
    /// `modelVersion`.
    pub model_version: String,
    /// Content parts of the first candidate, in order.
    pub parts: Vec<ResponsePart>,
    /// `finishReason` (`STOP`, `MAX_TOKENS`, `SAFETY`, …), if reported.
    pub finish_reason: Option<String>,
    /// `finishMessage`, if reported.
    pub finish_message: Option<String>,
    /// The candidate's safety ratings.
    pub safety_ratings: Vec<SafetyRating>,
    /// Token usage.
    pub usage: Usage,
}

/// Build the error for a blocked prompt (`promptFeedback.blockReason`).
pub fn blocked_prompt(feedback: &PromptFeedback) -> Option<LlmError> {
    let reason = feedback.block_reason.as_deref()?;
    let mut message = format!("the prompt was blocked by Gemini (blockReason: {reason}");
    let flagged: Vec<&str> = feedback
        .safety_ratings
        .iter()
        .filter(|r| r.blocked)
        .map(|r| r.category.as_str())
        .collect();
    if !flagged.is_empty() {
        message.push_str(", categories: ");
        message.push_str(&flagged.join(", "));
    }
    message.push(')');
    if let Some(detail) = feedback.block_reason_message.as_deref() {
        message.push_str(": ");
        message.extend(detail.chars().take(512));
    }
    Some(LlmError::provider(message))
}

/// The id for the `index`-th function call of a response.
pub fn call_id(api_id: Option<String>, response_id: &str, index: usize) -> String {
    match api_id {
        Some(id) if !id.is_empty() => id,
        _ if response_id.is_empty() => format!("{SYNTHETIC_CALL_ID_PREFIX}{index}"),
        _ => format!("{SYNTHETIC_CALL_ID_PREFIX}{response_id}_{index}"),
    }
}

impl GeminiResponse {
    /// Decode a wire response.
    ///
    /// # Errors
    ///
    /// [`LlmError`] with kind `Provider` when the prompt was blocked, and
    /// `InvalidResponse` when there is no candidate, or a function call
    /// without a name or with non-object arguments.
    pub(crate) fn from_wire(body: GenerateContentResponse) -> Result<Self, LlmError> {
        if let Some(err) = body.prompt_feedback.as_ref().and_then(blocked_prompt) {
            return Err(err);
        }
        let response_id = body.response_id.unwrap_or_default();
        let Some(candidate) = body.candidates.into_iter().next() else {
            return Err(LlmError::invalid_response("the response has no candidates"));
        };
        let mut parts = Vec::new();
        let mut calls = 0;
        for part in candidate.content.map(|c| c.parts).unwrap_or_default() {
            if let Some(p) = convert_part(part, &response_id, &mut calls)? {
                parts.push(p);
            }
        }
        Ok(Self {
            response_id,
            model_version: body.model_version.unwrap_or_default(),
            parts,
            finish_reason: candidate.finish_reason,
            finish_message: candidate.finish_message,
            safety_ratings: candidate
                .safety_ratings
                .into_iter()
                .map(SafetyRating::from)
                .collect(),
            usage: body
                .usage_metadata
                .as_ref()
                .map(Usage::from_wire)
                .unwrap_or_default(),
        })
    }

    /// Token usage.
    #[must_use]
    pub const fn usage(&self) -> &Usage {
        &self.usage
    }

    /// The visible text: every text part, concatenated. Thoughts are never
    /// included.
    #[must_use]
    pub fn text(&self) -> String {
        let mut out = String::new();
        for part in &self.parts {
            if let ResponsePart::Text { text, .. } = part {
                out.push_str(text);
            }
        }
        out
    }

    /// Thought summaries, concatenated (empty unless thoughts were asked for).
    #[must_use]
    pub fn thoughts(&self) -> String {
        let mut out = String::new();
        for part in &self.parts {
            if let ResponsePart::Thought { text, .. } = part {
                out.push_str(text);
            }
        }
        out
    }

    /// Function calls, with arguments as JSON text.
    #[must_use]
    pub fn tool_calls(&self) -> Vec<ToolCall> {
        self.parts
            .iter()
            .filter_map(|p| match p {
                ResponsePart::FunctionCall { id, name, args, .. } => {
                    Some(ToolCall::new(id.clone(), name.clone(), args.to_string()))
                }
                _ => None,
            })
            .collect()
    }

    /// Thought summaries and thought signatures as portable
    /// [`ReasoningBlock`]s, in order.
    ///
    /// A thought becomes a block with its text (and signature). A signature
    /// on a text or function-call part becomes a block with empty text and
    /// that signature; when the turn is sent back, it goes on the first
    /// function call, or on the last text part when there is none, which is
    /// where Gemini puts it.
    #[must_use]
    pub fn reasoning(&self) -> Vec<ReasoningBlock> {
        self.parts
            .iter()
            .filter_map(|p| match p {
                ResponsePart::Thought { text, signature } => {
                    let block = ReasoningBlock::new(text.clone());
                    Some(match signature {
                        Some(s) => block.with_signature(s.clone()),
                        None => block,
                    })
                }
                ResponsePart::Text {
                    signature: Some(s), ..
                }
                | ResponsePart::FunctionCall {
                    signature: Some(s), ..
                } => Some(ReasoningBlock::default().with_signature(s.clone())),
                _ => None,
            })
            .collect()
    }

    /// `true` when output was cut off at `maxOutputTokens`.
    #[must_use]
    pub fn is_truncated(&self) -> bool {
        self.finish_reason.as_deref() == Some("MAX_TOKENS")
    }

    /// `true` when a safety, recitation or policy filter stopped the output.
    #[must_use]
    pub fn is_filtered(&self) -> bool {
        matches!(self.finish_reason(), Some(FinishReason::ContentFilter))
    }

    /// The portable [`FinishReason`]. `STOP` with function calls is
    /// [`FinishReason::ToolCalls`].
    #[must_use]
    pub fn finish_reason(&self) -> Option<FinishReason> {
        let raw = self.finish_reason.as_deref()?;
        let has_calls = self
            .parts
            .iter()
            .any(|p| matches!(p, ResponsePart::FunctionCall { .. }));
        Some(match finish_reason(raw) {
            FinishReason::Stop if has_calls => FinishReason::ToolCalls,
            other => other,
        })
    }

    /// Convert to the portable [`GenerateResult`], keeping thoughts and
    /// signatures as [`GenerateResult::reasoning`] so
    /// [`GenerateResult::to_message`] sends them back on the next turn.
    #[must_use]
    pub fn to_generate_result(&self) -> GenerateResult {
        let result = GenerateResult::from_text(self.text())
            .with_tokens(self.usage.to_token_usage())
            .with_tool_calls(self.tool_calls())
            .with_reasoning(self.reasoning());
        match self.finish_reason() {
            Some(reason) => result.with_finish_reason(reason),
            None => result,
        }
    }
}

/// Turn a wire part into a response part; parts of kinds this crate does
/// not model yield `None`.
pub fn convert_part(
    part: Part,
    response_id: &str,
    calls: &mut usize,
) -> Result<Option<ResponsePart>, LlmError> {
    if let Some(call) = part.function_call {
        if call.name.is_empty() {
            return Err(LlmError::invalid_response("function call without a name"));
        }
        let args = match call.args {
            Value::Null => Value::Object(serde_json::Map::new()),
            obj @ Value::Object(_) => obj,
            _ => {
                return Err(LlmError::invalid_response(
                    "function call arguments are not a JSON object",
                ));
            }
        };
        let id = call_id(call.id, response_id, *calls);
        *calls += 1;
        return Ok(Some(ResponsePart::FunctionCall {
            id,
            name: call.name,
            args,
            signature: part.thought_signature,
        }));
    }
    Ok(match part.text {
        Some(text) if part.thought => Some(ResponsePart::Thought {
            text,
            signature: part.thought_signature,
        }),
        Some(text) => Some(ResponsePart::Text {
            text,
            signature: part.thought_signature,
        }),
        // A bare signature (streams end with one on an empty part).
        None => part.thought_signature.map(|signature| ResponsePart::Text {
            text: String::new(),
            signature: Some(signature),
        }),
    })
}

/// Map a Gemini `finishReason` onto the portable [`FinishReason`].
///
/// `STOP` is [`FinishReason::Stop`], `MAX_TOKENS` [`FinishReason::Length`];
/// the safety, recitation, blocklist, prohibited-content and personal-data
/// filters are [`FinishReason::ContentFilter`]. Anything else
/// (`MALFORMED_FUNCTION_CALL`, `LANGUAGE`, `OTHER`, …) is kept verbatim.
#[must_use]
pub fn finish_reason(reason: &str) -> FinishReason {
    match reason {
        "STOP" => FinishReason::Stop,
        "MAX_TOKENS" => FinishReason::Length,
        "SAFETY"
        | "RECITATION"
        | "BLOCKLIST"
        | "PROHIBITED_CONTENT"
        | "SPII"
        | "IMAGE_SAFETY"
        | "IMAGE_PROHIBITED_CONTENT"
        | "IMAGE_RECITATION" => FinishReason::ContentFilter,
        other => FinishReason::Other(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests")]

    use rune_chain_core::LlmErrorKind;

    use super::*;

    fn decode(json: &str) -> Result<GeminiResponse, LlmError> {
        GeminiResponse::from_wire(serde_json::from_str(json).unwrap())
    }

    #[test]
    fn finish_reasons() {
        assert_eq!(finish_reason("STOP"), FinishReason::Stop);
        assert_eq!(finish_reason("MAX_TOKENS"), FinishReason::Length);
        for r in [
            "SAFETY",
            "RECITATION",
            "BLOCKLIST",
            "PROHIBITED_CONTENT",
            "SPII",
        ] {
            assert_eq!(finish_reason(r), FinishReason::ContentFilter, "{r}");
        }
        assert_eq!(
            finish_reason("MALFORMED_FUNCTION_CALL"),
            FinishReason::Other("MALFORMED_FUNCTION_CALL".into())
        );
    }

    #[test]
    fn usage_mapping() {
        let u = Usage {
            prompt_tokens: 100,
            candidates_tokens: 20,
            thoughts_tokens: 30,
            cached_tokens: 60,
            tool_use_prompt_tokens: 5,
            total_tokens: Some(155),
        };
        let t = u.to_token_usage();
        assert_eq!(t.prompt_tokens, 105);
        assert_eq!(t.completion_tokens, 50);
        assert_eq!(t.cache_read_tokens, 60);
        assert_eq!(t.reasoning_tokens, 30);
        assert_eq!(t.total_tokens, 155);
        rune_chain_core::testing::check_token_usage(&t).unwrap();

        // Hostile counts never break the subset invariants.
        let u = Usage {
            prompt_tokens: u32::MAX,
            candidates_tokens: u32::MAX,
            thoughts_tokens: u32::MAX,
            cached_tokens: u32::MAX,
            tool_use_prompt_tokens: u32::MAX,
            total_tokens: Some(3),
        };
        let t = u.to_token_usage();
        assert!(t.cache_read_tokens <= t.prompt_tokens);
        assert!(t.reasoning_tokens <= t.completion_tokens);
    }

    #[test]
    fn decodes_text_thoughts_and_calls() {
        let r = decode(
            r#"{"responseId":"r1","modelVersion":"gemini-2.5-flash","candidates":[{"content":{"role":"model","parts":[
                {"text":"Let me think.","thought":true},
                {"text":"Checking the weather."},
                {"functionCall":{"name":"get_weather","args":{"city":"Paris"}},"thoughtSignature":"c2ln"},
                {"functionCall":{"id":"api-id","name":"get_time"}},
                {"executableCode":{"language":"PYTHON","code":"print(1)"}}
            ]},"finishReason":"STOP"}],
            "usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":5,"thoughtsTokenCount":7,"totalTokenCount":22}}"#,
        )
        .unwrap();
        assert_eq!(r.text(), "Checking the weather.");
        assert_eq!(r.thoughts(), "Let me think.");
        let calls = r.tool_calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].id, "gemini_call_r1_0");
        assert_eq!(calls[0].arguments, r#"{"city":"Paris"}"#);
        assert_eq!(calls[1].id, "api-id");
        assert_eq!(calls[1].arguments, "{}");
        assert_eq!(r.finish_reason(), Some(FinishReason::ToolCalls));
        let reasoning = r.reasoning();
        assert_eq!(reasoning.len(), 2);
        assert_eq!(reasoning[0].text, "Let me think.");
        assert_eq!(reasoning[1].text, "");
        assert_eq!(reasoning[1].signature.as_deref(), Some("c2ln"));
        let g = r.to_generate_result();
        assert_eq!(g.tokens.as_ref().unwrap().completion_tokens, 12);
        assert!(g.wants_tool_calls());
    }

    #[test]
    fn blocked_prompt_is_an_error() {
        let err = decode(
            r#"{"promptFeedback":{"blockReason":"SAFETY","safetyRatings":[
                {"category":"HARM_CATEGORY_DANGEROUS_CONTENT","probability":"HIGH","blocked":true}]}}"#,
        )
        .unwrap_err();
        assert_eq!(err.kind(), LlmErrorKind::Provider);
        assert!(err.message().contains("blockReason: SAFETY"));
        assert!(err.message().contains("HARM_CATEGORY_DANGEROUS_CONTENT"));
        assert!(!err.is_retryable());
    }

    #[test]
    fn rejects_malformed_responses() {
        assert_eq!(
            decode("{}").unwrap_err().kind(),
            LlmErrorKind::InvalidResponse
        );
        assert!(decode(
            r#"{"candidates":[{"content":{"parts":[{"functionCall":{"name":"f","args":[1]}}]}}]}"#
        )
        .is_err());
        assert!(
            decode(
                r#"{"candidates":[{"content":{"parts":[{"functionCall":{"name":"","args":{}}}]}}]}"#
            )
            .is_err()
        );
    }

    #[test]
    fn safety_stop_is_a_content_filter() {
        let r = decode(
            r#"{"candidates":[{"finishReason":"SAFETY","safetyRatings":[
                {"category":"HARM_CATEGORY_HARASSMENT","probability":"HIGH","blocked":true}]}]}"#,
        )
        .unwrap();
        assert!(r.is_filtered());
        assert_eq!(r.text(), "");
        assert!(r.safety_ratings[0].blocked);
    }
}

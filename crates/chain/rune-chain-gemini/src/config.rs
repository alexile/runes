//! Request options beyond the portable [`Llm`](rune_chain_core::Llm)
//! surface: thinking and safety settings.

use serde::Serialize;

use crate::types::ThinkingConfig;

/// How many tokens a model may spend thinking (`thinkingBudget`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ThinkingBudget {
    /// No thinking (`0`). Rejected by models whose thinking is always on.
    Off,
    /// The model decides (`-1`).
    Dynamic,
    /// A fixed budget. Each model accepts its own range (see
    /// [`ModelInfo::thinking`](crate::ModelInfo::thinking)).
    Tokens(u32),
}

/// Relative thinking depth (`thinkingLevel`), the recommended control on
/// Gemini 3 models. Gemini 2.5 models take a [`ThinkingBudget`] instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ThinkingLevel {
    /// As little thinking as the model allows.
    Minimal,
    /// Low latency and cost.
    Low,
    /// Balanced.
    Medium,
    /// Deepest reasoning (the Gemini 3 default).
    High,
}

impl ThinkingLevel {
    /// The wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Minimal => "minimal",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

/// Thinking configuration (`generationConfig.thinkingConfig`).
///
/// Set either a budget or a level, not both. With
/// [`with_thoughts`](Self::with_thoughts) the response carries thought
/// summaries, returned as [`ReasoningBlock`](rune_chain_core::ReasoningBlock)s
/// and never mixed into the response text.
///
/// ```rust
/// use rune_chain_gemini::{Thinking, ThinkingLevel};
///
/// let _flash = Thinking::budget(2048).with_thoughts();
/// let _pro3 = Thinking::level(ThinkingLevel::Low);
/// let _fast = Thinking::off();
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Thinking {
    /// `thinkingBudget`.
    pub budget: Option<ThinkingBudget>,
    /// `thinkingLevel`.
    pub level: Option<ThinkingLevel>,
    /// `includeThoughts`: return thought summaries.
    pub include_thoughts: bool,
}

impl Thinking {
    /// A fixed thinking budget.
    #[must_use]
    pub const fn budget(tokens: u32) -> Self {
        Self {
            budget: Some(ThinkingBudget::Tokens(tokens)),
            level: None,
            include_thoughts: false,
        }
    }

    /// Let the model pick its budget.
    #[must_use]
    pub const fn dynamic() -> Self {
        Self {
            budget: Some(ThinkingBudget::Dynamic),
            level: None,
            include_thoughts: false,
        }
    }

    /// Turn thinking off (budget `0`).
    #[must_use]
    pub const fn off() -> Self {
        Self {
            budget: Some(ThinkingBudget::Off),
            level: None,
            include_thoughts: false,
        }
    }

    /// A thinking level (Gemini 3).
    #[must_use]
    pub const fn level(level: ThinkingLevel) -> Self {
        Self {
            budget: None,
            level: Some(level),
            include_thoughts: false,
        }
    }

    /// Only ask for thought summaries, keeping the model's default depth.
    #[must_use]
    pub const fn thoughts() -> Self {
        Self {
            budget: None,
            level: None,
            include_thoughts: true,
        }
    }

    /// Also return thought summaries.
    #[must_use]
    pub const fn with_thoughts(mut self) -> Self {
        self.include_thoughts = true;
        self
    }

    pub(crate) fn to_wire(self) -> Result<ThinkingConfig, &'static str> {
        if self.budget.is_some() && self.level.is_some() {
            return Err("set a thinking budget or a thinking level, not both");
        }
        let thinking_budget = match self.budget {
            None => None,
            Some(ThinkingBudget::Off) => Some(0),
            Some(ThinkingBudget::Dynamic) => Some(-1),
            Some(ThinkingBudget::Tokens(0)) => {
                return Err("a thinking budget of 0 tokens is `Thinking::off()`");
            }
            Some(ThinkingBudget::Tokens(n)) => {
                Some(i32::try_from(n).map_err(|_| "thinking budget is too large")?)
            }
        };
        Ok(ThinkingConfig {
            thinking_budget,
            thinking_level: self.level.map(ThinkingLevel::as_str),
            include_thoughts: self.include_thoughts.then_some(true),
        })
    }
}

/// A harm category for [`SafetySetting`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[non_exhaustive]
pub enum HarmCategory {
    /// Harassment.
    #[serde(rename = "HARM_CATEGORY_HARASSMENT")]
    Harassment,
    /// Hate speech.
    #[serde(rename = "HARM_CATEGORY_HATE_SPEECH")]
    HateSpeech,
    /// Sexually explicit content.
    #[serde(rename = "HARM_CATEGORY_SEXUALLY_EXPLICIT")]
    SexuallyExplicit,
    /// Dangerous content.
    #[serde(rename = "HARM_CATEGORY_DANGEROUS_CONTENT")]
    DangerousContent,
    /// Civic integrity.
    #[serde(rename = "HARM_CATEGORY_CIVIC_INTEGRITY")]
    CivicIntegrity,
}

/// When a [`HarmCategory`] blocks content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum HarmBlockThreshold {
    /// Block content with a low or higher probability of harm.
    BlockLowAndAbove,
    /// Block medium or higher.
    BlockMediumAndAbove,
    /// Block only high.
    BlockOnlyHigh,
    /// Never block, but still report ratings.
    BlockNone,
    /// Turn the safety filter off for the category.
    Off,
}

/// One entry of the request's `safetySettings`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[non_exhaustive]
pub struct SafetySetting {
    /// The category.
    pub category: HarmCategory,
    /// Its threshold.
    pub threshold: HarmBlockThreshold,
}

impl SafetySetting {
    /// A setting for one category.
    #[must_use]
    pub const fn new(category: HarmCategory, threshold: HarmBlockThreshold) -> Self {
        Self {
            category,
            threshold,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests")]

    use serde_json::json;

    use super::*;

    #[test]
    fn thinking_wire_forms() {
        let wire = |t: Thinking| serde_json::to_value(t.to_wire().unwrap()).unwrap();
        assert_eq!(
            wire(Thinking::budget(1024)),
            json!({ "thinkingBudget": 1024 })
        );
        assert_eq!(wire(Thinking::off()), json!({ "thinkingBudget": 0 }));
        assert_eq!(
            wire(Thinking::dynamic().with_thoughts()),
            json!({ "thinkingBudget": -1, "includeThoughts": true })
        );
        assert_eq!(
            wire(Thinking::level(ThinkingLevel::High)),
            json!({ "thinkingLevel": "high" })
        );
        assert_eq!(
            wire(Thinking::thoughts()),
            json!({ "includeThoughts": true })
        );

        let both = Thinking {
            level: Some(ThinkingLevel::Low),
            ..Thinking::budget(10)
        };
        assert!(both.to_wire().is_err());
        assert!(Thinking::budget(0).to_wire().is_err());
        assert!(Thinking::budget(u32::MAX).to_wire().is_err());
    }

    #[test]
    fn safety_wire_form() {
        let s = SafetySetting::new(
            HarmCategory::DangerousContent,
            HarmBlockThreshold::BlockOnlyHigh,
        );
        assert_eq!(
            serde_json::to_value(s).unwrap(),
            json!({ "category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_ONLY_HIGH" })
        );
        let off = SafetySetting::new(HarmCategory::Harassment, HarmBlockThreshold::Off);
        assert_eq!(serde_json::to_value(off).unwrap()["threshold"], "OFF");
    }
}

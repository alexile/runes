//! Request-level settings: how long the model stays loaded, and thinking.

use std::time::Duration;

use serde_json::Value;

/// How long Ollama keeps the model loaded after a request (`keep_alive`).
///
/// Unset, the server default applies (5 minutes unless `OLLAMA_KEEP_ALIVE`
/// says otherwise).
///
/// ```rust
/// use std::time::Duration;
/// use rune_chain_ollama::{KeepAlive, Ollama};
///
/// let llm = Ollama::new().keep_alive(KeepAlive::For(Duration::from_secs(30 * 60)));
/// let pinned = Ollama::new().keep_alive(KeepAlive::Forever);
/// # let _ = (llm, pinned);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeepAlive {
    /// Keep the model loaded for this long after the request (rounded up to
    /// whole seconds).
    For(Duration),
    /// Keep the model loaded until the server stops (`-1`).
    Forever,
    /// Unload the model as soon as the request finishes (`0`).
    UnloadNow,
}

impl KeepAlive {
    pub(crate) fn to_value(self) -> Value {
        match self {
            Self::Forever => Value::from(-1),
            Self::UnloadNow => Value::from(0),
            Self::For(d) if d.is_zero() => Value::from(0),
            Self::For(d) => {
                let secs = d.as_secs().saturating_add(u64::from(d.subsec_nanos() > 0));
                Value::from(secs)
            }
        }
    }
}

/// Reasoning ("thinking") mode for thinking-capable models (`think`).
///
/// With thinking on, Ollama returns the reasoning separately from the answer:
/// it is reported as [`StreamEvent::Thinking`](crate::StreamEvent::Thinking)
/// and in [`ChatReply::thinking`](crate::ChatReply::thinking), and never mixed
/// into [`GenerateResult::generation`](rune_chain_core::GenerateResult::generation).
/// Models without thinking support reject the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Think {
    /// Enable thinking (`true`).
    On,
    /// Disable thinking (`false`), for models that think by default.
    Off,
    /// Low reasoning effort (`"low"`, e.g. `gpt-oss`).
    Low,
    /// Medium reasoning effort (`"medium"`).
    Medium,
    /// High reasoning effort (`"high"`).
    High,
}

impl Think {
    pub(crate) fn to_value(self) -> Value {
        match self {
            Self::On => Value::Bool(true),
            Self::Off => Value::Bool(false),
            Self::Low => Value::from("low"),
            Self::Medium => Value::from("medium"),
            Self::High => Value::from("high"),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn keep_alive_wire_values() {
        assert_eq!(KeepAlive::Forever.to_value(), json!(-1));
        assert_eq!(KeepAlive::UnloadNow.to_value(), json!(0));
        assert_eq!(KeepAlive::For(Duration::ZERO).to_value(), json!(0));
        assert_eq!(
            KeepAlive::For(Duration::from_millis(1)).to_value(),
            json!(1)
        );
        assert_eq!(
            KeepAlive::For(Duration::from_secs(300)).to_value(),
            json!(300)
        );
    }

    #[test]
    fn think_wire_values() {
        assert_eq!(Think::On.to_value(), json!(true));
        assert_eq!(Think::Off.to_value(), json!(false));
        assert_eq!(Think::High.to_value(), json!("high"));
    }
}

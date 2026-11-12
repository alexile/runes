//! What prompt and completion content may be put on spans.

use std::fmt;
use std::sync::Arc;

/// A redaction hook: takes text about to be recorded, returns what to
/// record instead.
pub type RedactFn = Arc<dyn Fn(&str) -> String + Send + Sync>;

/// Default cap, in characters, on each recorded text value.
pub const DEFAULT_MAX_CHARS: usize = 4_096;

/// Default cap on how many input messages are recorded (the most recent
/// ones are kept).
pub const DEFAULT_MAX_MESSAGES: usize = 32;

/// Marker appended to a value cut at the size cap.
pub const TRUNCATED_MARKER: &str = "…[truncated]";

/// Whether and how prompts, completions, tool arguments and tool results
/// are recorded on spans.
///
/// Capture is **off** by default: the content may hold personal data or
/// secrets. When on, every text value is passed through the redaction hook
/// first and then cut to [`max_chars`](Self::with_max_chars) characters;
/// only the last [`max_messages`](Self::with_max_messages) input messages
/// are recorded. Image parts are never recorded, only their presence.
///
/// # Examples
///
/// ```
/// use rune_otel_genai::ContentPolicy;
///
/// let policy = ContentPolicy::capture()
///     .with_max_chars(8)
///     .with_redactor(|text| text.replace("hunter2", "[SECRET]"));
/// assert_eq!(policy.apply("pw hunter2"), "pw [SECR…[truncated]");
/// assert!(!ContentPolicy::default().is_enabled());
/// ```
#[derive(Clone)]
pub struct ContentPolicy {
    enabled: bool,
    max_chars: usize,
    max_messages: usize,
    redactor: Option<RedactFn>,
}

impl Default for ContentPolicy {
    fn default() -> Self {
        Self::off()
    }
}

impl ContentPolicy {
    /// Record no content (the default).
    #[must_use]
    pub const fn off() -> Self {
        Self {
            enabled: false,
            max_chars: DEFAULT_MAX_CHARS,
            max_messages: DEFAULT_MAX_MESSAGES,
            redactor: None,
        }
    }

    /// Record content, with the default size caps and no redaction.
    #[must_use]
    pub fn capture() -> Self {
        Self {
            enabled: true,
            ..Self::off()
        }
    }

    /// Turn capture on or off, keeping the other settings.
    #[must_use]
    pub const fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Cap each recorded text value at `chars` characters.
    #[must_use]
    pub const fn with_max_chars(mut self, chars: usize) -> Self {
        self.max_chars = chars;
        self
    }

    /// Record at most the last `messages` input messages.
    #[must_use]
    pub const fn with_max_messages(mut self, messages: usize) -> Self {
        self.max_messages = messages;
        self
    }

    /// Pass every recorded text value through `redact` first.
    #[must_use]
    pub fn with_redactor(
        mut self,
        redact: impl Fn(&str) -> String + Send + Sync + 'static,
    ) -> Self {
        self.redactor = Some(Arc::new(redact));
        self
    }

    /// Redact with `rune-redact`'s default policy (emails, phone numbers,
    /// card numbers, credentials and other secrets).
    ///
    /// ```
    /// use rune_otel_genai::ContentPolicy;
    ///
    /// let policy = ContentPolicy::capture().with_default_redaction();
    /// assert_eq!(policy.apply("mail user@example.com"), "mail [EMAIL]");
    /// ```
    #[cfg(feature = "redact")]
    #[must_use]
    pub fn with_default_redaction(self) -> Self {
        self.with_redactor(rune_redact::redact)
    }

    /// Whether content is recorded at all.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// The per-value character cap.
    #[must_use]
    pub const fn max_chars(&self) -> usize {
        self.max_chars
    }

    /// The input message cap.
    #[must_use]
    pub const fn max_messages(&self) -> usize {
        self.max_messages
    }

    /// `text` as it would be recorded: redacted, then cut to the cap.
    #[must_use]
    pub fn apply(&self, text: &str) -> String {
        self.apply_cut(text, false)
    }

    /// Like [`apply`](Self::apply), for text the caller already cut short:
    /// the truncation marker is added either way.
    #[must_use]
    pub fn apply_cut(&self, text: &str, already_cut: bool) -> String {
        let mut out = self
            .redactor
            .as_ref()
            .map_or_else(|| text.to_owned(), |redact| redact(text));
        let cut = match out.char_indices().nth(self.max_chars) {
            Some((at, _)) => {
                out.truncate(at);
                true
            }
            None => false,
        };
        if cut || already_cut {
            out.push_str(TRUNCATED_MARKER);
        }
        out
    }
}

impl fmt::Debug for ContentPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContentPolicy")
            .field("enabled", &self.enabled)
            .field("max_chars", &self.max_chars)
            .field("max_messages", &self.max_messages)
            .field("redactor", &self.redactor.as_ref().map(|_| "Fn"))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caps_on_char_boundaries() {
        let p = ContentPolicy::capture().with_max_chars(2);
        assert_eq!(p.apply("日本語"), "日本…[truncated]");
        assert_eq!(p.apply("ab"), "ab");
        assert_eq!(p.apply_cut("ab", true), "ab…[truncated]");
        assert_eq!(ContentPolicy::capture().with_max_chars(0).apply(""), "");
    }

    #[test]
    fn redacts_before_cutting() {
        let p = ContentPolicy::capture()
            .with_max_chars(5)
            .with_redactor(|t| t.replace("secret-token", "[X]"));
        // The secret straddles the cap; redacting first means none of it leaks.
        assert_eq!(p.apply("key secret-token"), "key […[truncated]");
        assert!(format!("{p:?}").contains("\"Fn\""));
    }
}

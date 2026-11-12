//! A JSON event formatter that redacts every value on its own.
//!
//! Redacting a finished JSON line with text patterns can break it: a rule
//! such as `password = "…"` may swallow a closing quote. Here each value is
//! redacted *before* it is escaped, so the output is always valid JSON and
//! only values change; keys, levels and targets come from code, not input.

use std::fmt::{self, Write as _};

use rune_redact::Redactor;
use tracing_core::field::{Field, Visit};
use tracing_core::span::Record;
use tracing_core::{Event, Subscriber};
use tracing_subscriber::field::RecordFields;
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::time::{FormatTime, SystemTime};
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields, FormattedFields};
use tracing_subscriber::registry::LookupSpan;

/// Formats span and event fields as a JSON object body (`"k":v,"k2":v2`),
/// redacting every value.
///
/// Span fields are stored in this form by the fmt layer, and
/// [`JsonFormat`] splices them into each event's `spans` list.
#[derive(Debug, Clone)]
pub struct JsonFields {
    redactor: Redactor,
}

impl JsonFields {
    /// Redacts values with `redactor`.
    #[must_use]
    pub const fn new(redactor: Redactor) -> Self {
        Self { redactor }
    }
}

impl<'w> FormatFields<'w> for JsonFields {
    fn format_fields<R: RecordFields>(&self, mut writer: Writer<'w>, fields: R) -> fmt::Result {
        let mut buf = String::new();
        fields.record(&mut JsonVisitor::new(&mut buf, &self.redactor, true));
        writer.write_str(&buf)
    }

    fn add_fields(
        &self,
        current: &'w mut FormattedFields<Self>,
        fields: &Record<'_>,
    ) -> fmt::Result {
        let first = current.fields.is_empty();
        fields.record(&mut JsonVisitor::new(
            &mut current.fields,
            &self.redactor,
            first,
        ));
        Ok(())
    }
}

/// Writes each event as one JSON object per line:
///
/// ```json
/// {"timestamp":"…","level":"INFO","target":"app","fields":{"message":"…"},"spans":[{"name":"req","user":"[EMAIL]"}]}
/// ```
///
/// `timestamp` and `target` can be left out; `spans` (root first) is left out
/// when the event is outside any span. Pair it with [`JsonFields`].
#[derive(Debug, Clone)]
pub struct JsonFormat {
    redactor: Redactor,
    timestamps: bool,
    target: bool,
}

impl JsonFormat {
    /// A formatter with timestamps and targets, redacting with `redactor`.
    #[must_use]
    pub const fn new(redactor: Redactor) -> Self {
        Self {
            redactor,
            timestamps: true,
            target: true,
        }
    }

    /// Includes (`true`, the default) or omits the RFC 3339 `timestamp`.
    #[must_use]
    pub const fn with_timestamps(mut self, on: bool) -> Self {
        self.timestamps = on;
        self
    }

    /// Includes (`true`, the default) or omits the event's `target`.
    #[must_use]
    pub const fn with_target(mut self, on: bool) -> Self {
        self.target = on;
        self
    }
}

impl<S> FormatEvent<S, JsonFields> for JsonFormat
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, JsonFields>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let meta = event.metadata();
        let mut out = String::with_capacity(256);
        out.push('{');
        if self.timestamps {
            let mut ts = String::new();
            SystemTime.format_time(&mut Writer::new(&mut ts))?;
            out.push_str("\"timestamp\":");
            push_json_str(&mut out, &ts);
            out.push(',');
        }
        out.push_str("\"level\":");
        push_json_str(&mut out, meta.level().as_str());
        if self.target {
            out.push_str(",\"target\":");
            push_json_str(&mut out, meta.target());
        }
        out.push_str(",\"fields\":{");
        event.record(&mut JsonVisitor::new(&mut out, &self.redactor, true));
        out.push('}');

        if let Some(scope) = ctx.event_scope() {
            out.push_str(",\"spans\":[");
            for (i, span) in scope.from_root().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str("{\"name\":");
                push_json_str(&mut out, span.name());
                if let Some(fields) = span.extensions().get::<FormattedFields<JsonFields>>()
                    && !fields.fields.is_empty()
                {
                    out.push(',');
                    out.push_str(&fields.fields);
                }
                out.push('}');
            }
            out.push(']');
        }
        out.push_str("}\n");
        writer.write_str(&out)
    }
}

/// Records fields as `"key":value` pairs, redacting each value.
struct JsonVisitor<'a> {
    out: &'a mut String,
    redactor: &'a Redactor,
    first: bool,
    scratch: String,
}

impl<'a> JsonVisitor<'a> {
    const fn new(out: &'a mut String, redactor: &'a Redactor, first: bool) -> Self {
        Self {
            out,
            redactor,
            first,
            scratch: String::new(),
        }
    }

    fn key(&mut self, field: &Field) {
        if !self.first {
            self.out.push(',');
        }
        self.first = false;
        let name = field.name();
        push_json_str(self.out, name.strip_prefix("r#").unwrap_or(name));
        self.out.push(':');
    }

    fn string(&mut self, field: &Field, value: &str) {
        self.key(field);
        self.scratch.clear();
        self.redactor.redact_into(value, &mut self.scratch);
        push_json_str(self.out, &self.scratch);
    }

    /// A number stays a JSON number unless the redactor rewrites it (a card
    /// number or SSN logged as an integer), in which case the redacted text
    /// is written as a string.
    fn number(&mut self, field: &Field, text: &str) {
        self.key(field);
        self.scratch.clear();
        self.redactor.redact_into(text, &mut self.scratch);
        if self.scratch == text {
            self.out.push_str(text);
        } else {
            push_json_str(self.out, &self.scratch);
        }
    }
}

impl Visit for JsonVisitor<'_> {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.string(field, value);
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        let text = format!("{value:?}");
        self.string(field, &text);
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        let text = value.to_string();
        self.string(field, &text);
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.key(field);
        self.out.push_str(if value { "true" } else { "false" });
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.number(field, &value.to_string());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.number(field, &value.to_string());
    }

    fn record_i128(&mut self, field: &Field, value: i128) {
        self.number(field, &value.to_string());
    }

    fn record_u128(&mut self, field: &Field, value: u128) {
        self.number(field, &value.to_string());
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        if value.is_finite() {
            self.number(field, &value.to_string());
        } else {
            // NaN and infinities have no JSON number form.
            self.string(field, &value.to_string());
        }
    }
}

/// Appends `s` as a quoted JSON string (RFC 8259 §7).
pub fn push_json_str(out: &mut String, s: &str) {
    out.reserve(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 || c == '\u{7f}' => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::push_json_str;

    fn quoted(s: &str) -> String {
        let mut out = String::new();
        push_json_str(&mut out, s);
        out
    }

    #[test]
    fn escapes_specials() {
        assert_eq!(quoted("a\"b\\c"), r#""a\"b\\c""#);
        assert_eq!(quoted("x\ny\tz\r"), r#""x\ny\tz\r""#);
        assert_eq!(quoted("\u{1}\u{7f}"), r#""\u0001\u007f""#);
        assert_eq!(quoted("héllo ✓"), "\"héllo ✓\"");
    }

    #[test]
    fn escaped_text_round_trips_through_a_json_parser() {
        let s = "quote \" slash \\ nul \0 bell \u{7} emoji 🦀";
        let back: String = serde_json::from_str(&quoted(s)).unwrap();
        assert_eq!(back, s);
    }
}

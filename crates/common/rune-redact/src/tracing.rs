//! `tracing-subscriber` integration: redact log output and log fields.

use std::fmt;

use tracing_subscriber::field::RecordFields;
use tracing_subscriber::fmt::format::{DefaultFields, Writer};
use tracing_subscriber::fmt::{FormatFields, MakeWriter};

use crate::redactor::Redactor;
use crate::stream::{RedactingWriter, StreamRedactor};

/// A [`MakeWriter`] that redacts every formatted event before it reaches the
/// inner writer: message, event fields, span fields, everything the fmt
/// layer prints.
///
/// Each event gets its own [`RedactingWriter`] in line mode, finished when
/// the fmt layer drops it, so nothing is held back between events.
///
/// # Example
///
/// ```rust
/// use rune_redact::{RedactingMakeWriter, Redactor};
///
/// let subscriber = tracing_subscriber::fmt()
///     .with_writer(RedactingMakeWriter::new(std::io::stderr, Redactor::default()))
///     .finish();
/// # drop(subscriber);
/// ```
#[derive(Debug, Clone)]
pub struct RedactingMakeWriter<M> {
    inner: M,
    redactor: Redactor,
}

impl<M> RedactingMakeWriter<M> {
    /// Wraps `inner`, redacting with `redactor`.
    pub const fn new(inner: M, redactor: Redactor) -> Self {
        Self { inner, redactor }
    }

    fn wrap<W: std::io::Write>(&self, writer: W) -> RedactingWriter<W> {
        RedactingWriter::with_stream(
            writer,
            StreamRedactor::new(self.redactor.clone()).with_line_boundaries(true),
        )
    }
}

impl<'a, M: MakeWriter<'a>> MakeWriter<'a> for RedactingMakeWriter<M> {
    type Writer = RedactingWriter<M::Writer>;

    fn make_writer(&'a self) -> Self::Writer {
        self.wrap(self.inner.make_writer())
    }

    fn make_writer_for(&'a self, meta: &tracing_core::Metadata<'_>) -> Self::Writer {
        self.wrap(self.inner.make_writer_for(meta))
    }
}

/// A [`FormatFields`] wrapper that redacts field values (of events and of
/// spans) as they are formatted, leaving the rest of the line (timestamp,
/// level, target) untouched.
///
/// # Example
///
/// ```rust
/// use rune_redact::{RedactingFields, Redactor};
///
/// let subscriber = tracing_subscriber::fmt()
///     .fmt_fields(RedactingFields::new(Redactor::default()))
///     .finish();
/// # drop(subscriber);
/// ```
#[derive(Debug, Clone)]
pub struct RedactingFields<F = DefaultFields> {
    inner: F,
    redactor: Redactor,
}

impl RedactingFields<DefaultFields> {
    /// Redacts the output of [`DefaultFields`].
    #[must_use]
    pub fn new(redactor: Redactor) -> Self {
        Self::wrap(DefaultFields::new(), redactor)
    }
}

impl<F> RedactingFields<F> {
    /// Redacts the output of another field formatter.
    pub const fn wrap(inner: F, redactor: Redactor) -> Self {
        Self { inner, redactor }
    }
}

impl<'w, F> FormatFields<'w> for RedactingFields<F>
where
    F: for<'x> FormatFields<'x> + 'static,
{
    fn format_fields<R: RecordFields>(&self, mut writer: Writer<'w>, fields: R) -> fmt::Result {
        let mut raw = String::new();
        self.inner.format_fields(Writer::new(&mut raw), fields)?;
        let mut out = String::with_capacity(raw.len());
        self.redactor.redact_into(&raw, &mut out);
        fmt::Write::write_str(&mut writer, &out)
    }
}

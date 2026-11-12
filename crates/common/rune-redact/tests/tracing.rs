//! The `tracing` integration redacts event and span fields.

use std::io;
use std::sync::{Arc, Mutex, PoisonError};

use rune_redact::{Policy, RedactingFields, RedactingMakeWriter, Redactor, Replacement};
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Capture {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap_or_else(PoisonError::into_inner)).into_owned()
    }
}

impl io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Capture {
    type Writer = Self;
    fn make_writer(&'a self) -> Self {
        self.clone()
    }
}

fn emit() {
    let span = tracing::info_span!("request", user = "bob@example.com", ip = "10.1.2.3");
    let _guard = span.enter();
    tracing::info!(
        auth = "Bearer abcdef0123456789",
        "card 4111 1111 1111 1111 charged"
    );
}

#[test]
fn make_writer_redacts_spans_and_events() {
    let capture = Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(RedactingMakeWriter::new(
            capture.clone(),
            Redactor::default(),
        ))
        .finish();
    tracing::subscriber::with_default(subscriber, emit);

    let out = capture.text();
    assert!(
        out.contains("request{user=\"[EMAIL]\" ip=\"[IP]\"}"),
        "{out}"
    );
    assert!(out.contains("card [CC] charged"), "{out}");
    assert!(out.contains("auth=\"[BEARER]\""), "{out}");
    for secret in ["bob@example.com", "10.1.2.3", "4111", "abcdef0123456789"] {
        assert!(!out.contains(secret), "{secret} leaked: {out}");
    }
}

#[test]
fn field_formatter_redacts_spans_and_events_consistently() {
    let capture = Capture::default();
    let redactor =
        Redactor::new(Policy::default().with_replacement(Replacement::Tokenize)).unwrap();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(capture.clone())
        .fmt_fields(RedactingFields::new(redactor.clone()))
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        emit();
        let span = tracing::info_span!("again", user = "bob@example.com");
        let _guard = span.enter();
        tracing::warn!("done");
    });

    let out = capture.text();
    assert!(
        out.contains("request{user=\"[EMAIL_1]\" ip=\"[IP_1]\"}"),
        "{out}"
    );
    assert!(out.contains("again{user=\"[EMAIL_1]\"}"), "{out}");
    assert!(out.contains("card [CC_1] charged"), "{out}");
    assert!(!out.contains("bob@example.com"), "{out}");
    assert_eq!(redactor.restore("[EMAIL_1]"), "bob@example.com");
}

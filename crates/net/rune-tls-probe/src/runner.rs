//! The tokio scan loop over `rune-service-probe`'s [`Runner`].

use std::sync::{Arc, Mutex, PoisonError};

use rune_service_probe::{Runner, Target};

use crate::probe::TlsHelloProbe;
use crate::{Error, Outcome, Report, ScanOptions, Scanner};

/// Scans `target`: one TCP connection per hello, each bounded by the
/// runner's timeouts and budgets, until the [`Scanner`] is done.
///
/// Read-only: every connection sends one `ClientHello`, reads the server's
/// first answer and closes. No session is completed, no key material or
/// application data is sent. Scope is the caller's: probe only systems
/// you are authorised to assess, and pin the checked address with
/// [`Target::with_addr`].
///
/// If [`ScanOptions::server_name`] is unset, the target's host name is
/// sent as SNI (IP literals never are).
///
/// ```no_run
/// use rune_service_probe::{Options, Runner, Target};
/// use rune_tls_probe::{ScanOptions, scan};
///
/// # async fn demo() -> Result<(), rune_tls_probe::Error> {
/// let runner = Runner::new(Options::default());
/// let target = Target::new("legacy.internal.example", 443);
/// let report = scan(&runner, &target, &ScanOptions::default()).await?;
/// for finding in report.findings(&target) {
///     println!("{} {}", finding.check_id, finding.title);
/// }
/// # Ok(()) }
/// ```
///
/// # Errors
///
/// [`Error::Probe`] when the first connection fails (the target is
/// unreachable). Later connection failures are recorded as
/// [`Outcome::Unreachable`] and listed in [`Report::anomalies`].
pub async fn scan(
    runner: &Runner,
    target: &Target,
    options: &ScanOptions,
) -> Result<Report, Error> {
    let mut options = options.clone();
    if options.server_name.is_none() {
        options.server_name = Some(target.host.clone());
    }
    let mut scanner = Scanner::new(options);
    let mut first = true;
    while let Some(offer) = scanner.next_offer() {
        let sink = Arc::new(Mutex::new(None));
        let probe = TlsHelloProbe::with_sink(offer, Arc::clone(&sink));
        let result = runner.probe(&probe, target).await;
        let stored = sink.lock().unwrap_or_else(PoisonError::into_inner).take();
        let outcome = match (stored, result) {
            (Some(outcome), _) => outcome,
            (None, Err(error)) if error.is_unreachable() => {
                if first {
                    return Err(Error::Probe(error));
                }
                Outcome::Unreachable {
                    reason: error.to_string(),
                }
            }
            (None, Err(error)) => Outcome::NotTls {
                reason: error.to_string(),
            },
            (None, Ok(_)) => Outcome::NoResponse,
        };
        first = false;
        scanner.record(&outcome);
    }
    Ok(scanner.finish())
}

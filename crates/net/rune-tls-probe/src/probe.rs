//! `rune-service-probe` integration: one hello as a [`ServiceProbe`].

use std::hash::{BuildHasher, RandomState};
use std::sync::{Arc, Mutex, PoisonError};

use rune_service_probe::{
    Action, End, Error as ProbeError, ProbeSession, ServiceInfo, ServiceProbe, Target, TlsSupport,
};

use crate::{Offer, Outcome, ResponseReader, suite_label};

/// Ports where TLS is spoken from the first byte.
const TLS_PORTS: &[u16] = &[
    443, 465, 563, 636, 853, 989, 990, 992, 993, 994, 995, 5061, 8443,
];

/// A fresh client random. It only has to differ between hellos: no key is
/// ever derived from it, since the probe stops at the `ServerHello`.
pub fn client_random() -> [u8; 32] {
    let state = RandomState::new();
    let mut random = [0; 32];
    for (i, chunk) in random.chunks_mut(8).enumerate() {
        chunk.copy_from_slice(&state.hash_one(i).to_be_bytes());
    }
    random
}

/// Sends one [`Offer`] and reads the answer: a read-only
/// [`ServiceProbe`] for `rune-service-probe` runners and probe sets.
///
/// [`ServiceInfo`]: service `tls`, the negotiated version as `version` and
/// capability, and details `tls.cipher_suite`, `tls.compression_method`,
/// `tls.secure_renegotiation` (or `tls.alert` for a refusal). A peer that
/// does not answer in TLS gives [`ProbeError::Unrecognized`]. For a full
/// version and cipher enumeration use [`scan`](crate::scan) or
/// [`Scanner`](crate::Scanner).
///
/// ```
/// use rune_service_probe::{Options, Target, simulate};
/// use rune_tls_hello::{CipherSuite, ProtocolVersion, ServerHello};
/// use rune_tls_probe::{Offer, TlsHelloProbe};
///
/// let probe = TlsHelloProbe::new(Offer::new(ProtocolVersion::TLS_1_0, [CipherSuite(0x0005)]));
/// let reply = ServerHello::new()
///     .with_legacy_version(ProtocolVersion::TLS_1_0)
///     .with_cipher_suite(CipherSuite(0x0005))
///     .to_records(ProtocolVersion::TLS_1_0, 16_384)?;
/// let sim = simulate(&probe, &Target::new("legacy.test", 443), &[&reply], &Options::default())?;
/// let info = sim.result?;
/// assert_eq!(info.version.as_deref(), Some("TLSv1.0"));
/// assert_eq!(info.details["tls.cipher_suite"], "TLS_RSA_WITH_RC4_128_SHA");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone)]
pub struct TlsHelloProbe {
    offer: Offer,
    sink: Option<Arc<Mutex<Option<Outcome>>>>,
}

impl TlsHelloProbe {
    /// A probe sending `offer`.
    #[must_use]
    pub const fn new(offer: Offer) -> Self {
        Self { offer, sink: None }
    }

    /// The offer sent.
    #[must_use]
    pub const fn offer(&self) -> &Offer {
        &self.offer
    }

    /// A probe that also stores the typed [`Outcome`] for the scanner.
    #[cfg(any(feature = "tokio", test))]
    pub(crate) const fn with_sink(offer: Offer, sink: Arc<Mutex<Option<Outcome>>>) -> Self {
        Self {
            offer,
            sink: Some(sink),
        }
    }
}

impl ServiceProbe for TlsHelloProbe {
    fn id(&self) -> &'static str {
        "tls"
    }

    fn default_ports(&self) -> &[u16] {
        TLS_PORTS
    }

    fn session(&self, _target: &Target) -> Box<dyn ProbeSession> {
        Box::new(Session {
            hello: self.offer.to_records(client_random()),
            reader: ResponseReader::new(),
            outcome: None,
            sink: self.sink.clone(),
        })
    }
}

struct Session {
    hello: Result<Vec<u8>, crate::Error>,
    reader: ResponseReader,
    outcome: Option<Outcome>,
    sink: Option<Arc<Mutex<Option<Outcome>>>>,
}

impl ProbeSession for Session {
    fn start(&mut self) -> Action {
        self.hello
            .as_ref()
            .map_or(Action::Done, |hello| Action::Send(hello.clone()))
    }

    fn on_data(&mut self, data: &[u8]) -> Action {
        match self.reader.feed(data) {
            Some(outcome) => {
                self.outcome = Some(outcome);
                Action::Done
            }
            None => Action::Receive,
        }
    }

    fn finish(&mut self, _end: End) -> Result<ServiceInfo, ProbeError> {
        if let Err(error) = &self.hello {
            return Err(ProbeError::unrecognized(
                "tls",
                format!("cannot build the hello: {error}"),
            ));
        }
        let outcome = self.outcome.take().unwrap_or_else(|| self.reader.finish());
        if let Some(sink) = &self.sink {
            *sink.lock().unwrap_or_else(PoisonError::into_inner) = Some(outcome.clone());
        }
        match outcome {
            Outcome::Accepted(accepted) => {
                let version = accepted.version.to_string();
                Ok(ServiceInfo::new("tls")
                    .with_tls(TlsSupport::Implicit)
                    .with_version(version.clone())
                    .push_capability(version)
                    .with_detail("tls.cipher_suite", suite_label(accepted.cipher_suite))
                    .with_detail(
                        "tls.compression_method",
                        accepted.compression_method.to_string(),
                    )
                    .with_detail(
                        "tls.secure_renegotiation",
                        accepted.secure_renegotiation.to_string(),
                    ))
            }
            Outcome::Alert(alert) => Ok(ServiceInfo::new("tls")
                .with_tls(TlsSupport::Implicit)
                .with_detail("tls.alert", alert.description.to_string())),
            Outcome::NoResponse => Err(ProbeError::no_response("tls")),
            Outcome::NotTls { reason } | Outcome::Unreachable { reason } => {
                Err(ProbeError::unrecognized("tls", reason))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rune_service_probe::{Options, simulate};
    use rune_tls_hello::{CipherSuite, ProtocolVersion};

    #[test]
    fn randoms_differ() {
        assert_ne!(client_random(), client_random());
    }

    #[test]
    fn alert_and_garbage() {
        let probe = TlsHelloProbe::new(Offer::new(ProtocolVersion::SSL_3_0, [CipherSuite(0x000a)]));
        let target = Target::new("x.test", 443);
        let sim = simulate(
            &probe,
            &target,
            &[&[21, 3, 0, 0, 2, 2, 40]],
            &Options::default(),
        )
        .unwrap();
        assert_eq!(sim.sent.len(), 1);
        assert_eq!(
            sim.result.unwrap().details["tls.alert"],
            "handshake_failure"
        );

        let sim = simulate(
            &probe,
            &target,
            &[b"SSH-2.0-OpenSSH_9.6\r\n"],
            &Options::default(),
        )
        .unwrap();
        assert!(matches!(sim.result, Err(ProbeError::Unrecognized { .. })));
        let sim = simulate(&probe, &target, &[], &Options::default()).unwrap();
        assert!(matches!(sim.result, Err(ProbeError::NoResponse { .. })));
    }

    #[test]
    fn sink_receives_outcome() {
        let sink = Arc::new(Mutex::new(None));
        let probe =
            TlsHelloProbe::with_sink(Offer::new(ProtocolVersion::TLS_1_2, []), Arc::clone(&sink));
        let _ = simulate(
            &probe,
            &Target::new("x.test", 443),
            &[&[21, 3, 3, 0, 2, 2, 70]],
            &Options::default(),
        );
        assert!(
            sink.lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .is_alert(rune_tls_hello::AlertDescription::PROTOCOL_VERSION)
        );
    }
}

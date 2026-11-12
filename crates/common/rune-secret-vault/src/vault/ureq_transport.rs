//! [`UreqTransport`]: a blocking HTTP(S) transport built on `ureq`.

use std::fmt;
use std::time::Duration;

use super::{VaultRequest, VaultResponse, VaultTransport};
use crate::error::BoxError;

/// A blocking [`VaultTransport`] using `ureq` with rustls and the webpki
/// root certificates.
///
/// Redirects are never followed (a `3xx` comes back as a response, so the
/// token is not sent to another host), non-2xx statuses are returned as
/// responses, and bodies are capped at 1 MiB by default.
///
/// ```no_run
/// use rune_secret_ref::SecretValue;
/// use rune_secret_vault::{SecretProvider, UreqTransport, VaultConfig, VaultProvider};
///
/// let token = SecretValue::new(std::env::var("VAULT_TOKEN")?);
/// let config = VaultConfig::new("https://vault.example:8200", token)?;
/// let vault = VaultProvider::new(config, UreqTransport::new());
/// let password = vault.resolve(&"vault:secret/app/db#password".parse()?)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone)]
pub struct UreqTransport {
    agent: ureq::Agent,
    max_body: u64,
}

impl UreqTransport {
    /// A transport with a 30-second overall timeout per request.
    #[must_use]
    pub fn new() -> Self {
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(30)))
            .build()
            .new_agent();
        Self::from_agent(agent)
    }

    /// A transport using a preconfigured agent (proxy, timeouts, custom
    /// TLS roots). Status handling and redirects are still overridden per
    /// request as described on the type.
    #[must_use]
    pub const fn from_agent(agent: ureq::Agent) -> Self {
        Self {
            agent,
            max_body: 1024 * 1024,
        }
    }

    /// Sets the largest response body read, in bytes. Default 1 MiB.
    #[must_use]
    pub const fn with_max_body(mut self, max_body: u64) -> Self {
        self.max_body = max_body;
        self
    }
}

impl Default for UreqTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for UreqTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UreqTransport")
            .field("max_body", &self.max_body)
            .finish_non_exhaustive()
    }
}

impl VaultTransport for UreqTransport {
    fn get(&self, request: &VaultRequest) -> Result<VaultResponse, BoxError> {
        let mut builder = self
            .agent
            .get(&request.url)
            .config()
            .http_status_as_error(false)
            .max_redirects(0)
            .max_redirects_will_error(false)
            .build();
        for (name, value) in request.headers() {
            builder = builder.header(name, value);
        }
        let mut response = builder.call()?;
        let status = response.status().as_u16();
        let body = response
            .body_mut()
            .with_config()
            .limit(self.max_body)
            .read_to_vec()?;
        Ok(VaultResponse::new(status, body))
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::thread;

    use rune_secret_ref::SecretValue;

    use super::*;
    use crate::{ProviderError, SecretProvider, VaultConfig, VaultProvider};

    const TOKEN: &str = "hvs.loopback-token";
    const SECRET: &str = "loopback-s3cret";

    /// Serves one canned HTTP response on a loopback port and hands back
    /// the request head it received.
    fn serve_once(status_line: &'static str, body: String) -> (String, thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream);
            let mut head = String::new();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
                head.push_str(&line);
            }
            let mut stream = reader.into_inner();
            write!(
                stream,
                "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
            head
        });
        (address, handle)
    }

    fn provider(address: &str) -> VaultProvider<UreqTransport> {
        let config = VaultConfig::new(address, SecretValue::new(TOKEN))
            .unwrap()
            .with_namespace("ns1");
        VaultProvider::new(config, UreqTransport::default())
    }

    #[test]
    fn reads_a_kv2_secret_over_http() {
        let body = format!(r#"{{"data":{{"data":{{"token":"{SECRET}"}},"metadata":{{}}}}}}"#);
        let (address, server) = serve_once("200 OK", body);
        let value = provider(&address)
            .resolve(&"vault:secret/my app#token".parse().unwrap())
            .unwrap();
        assert_eq!(value.expose(), SECRET);

        let head = server.join().unwrap().to_ascii_lowercase();
        assert!(
            head.starts_with("get /v1/secret/data/my%20app http/1.1"),
            "{head}"
        );
        assert!(head.contains(&format!("x-vault-token: {}", TOKEN.to_ascii_lowercase())));
        assert!(head.contains("x-vault-namespace: ns1"));
        assert!(head.contains("x-vault-request: true"));
    }

    #[test]
    fn error_statuses_and_redirects_are_responses() {
        let (address, server) = serve_once(
            "403 Forbidden",
            r#"{"errors":["permission denied"]}"#.into(),
        );
        let error = provider(&address)
            .resolve(&"vault:secret/app#token".parse().unwrap())
            .unwrap_err();
        assert!(
            matches!(error, ProviderError::PermissionDenied { .. }),
            "{error:?}"
        );
        server.join().unwrap();

        let (address, server) = serve_once(
            "307 Temporary Redirect\r\nLocation: http://127.0.0.1:9/x",
            String::new(),
        );
        let error = provider(&address)
            .resolve(&"vault:secret/app#token".parse().unwrap())
            .unwrap_err();
        assert!(
            matches!(error, ProviderError::HttpStatus { status: 307, .. }),
            "{error:?}"
        );
        server.join().unwrap();
    }

    #[test]
    fn connection_failure_is_a_transport_error() {
        // Bind then drop, so the port is very likely closed.
        let address = {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            format!("http://{}", listener.local_addr().unwrap())
        };
        let error = provider(&address)
            .resolve(&"vault:secret/app#token".parse().unwrap())
            .unwrap_err();
        assert!(
            matches!(error, ProviderError::Transport { .. }),
            "{error:?}"
        );
        assert!(!format!("{error} {error:?}").contains(TOKEN));
    }
}

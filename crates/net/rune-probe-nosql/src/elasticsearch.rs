//! Elasticsearch and `OpenSearch`: `GET /` and `GET /_cluster/health`.
//!
//! The root endpoint returns the node and cluster name and the version;
//! `/_cluster/health` returns the cluster status and node counts. Both are
//! read-only. A `200` without credentials means the REST API, and with it
//! every index, is open; `401` means security is on.
//!
//! The probe speaks plain HTTP. For a cluster behind TLS (the default
//! since Elasticsearch 8), wrap the stream yourself and run the probe with
//! `Runner::probe_stream`.

use rune_service_probe::rune_finding::{Confidence, Evidence, Remediation, Severity, TaxonomyRef};
use rune_service_probe::{
    Action, AuthRequirement, End, ProbeSession, ServiceInfo, ServiceProbe, Target,
};
use serde_json::Value;

use crate::http::{Response, get_request, parse_response};
use crate::wire::text;

/// Read-only Elasticsearch (and `OpenSearch`) probe.
///
/// Reports product (`Elasticsearch` or `OpenSearch`), version, cluster
/// and node name, Lucene version, cluster health, and:
///
/// | Check id                        | When                                               |
/// | ------------------------------- | -------------------------------------------------- |
/// | `elasticsearch.unauthenticated` | `GET /` returns cluster details without credentials (CWE-306) |
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ElasticsearchProbe;

impl ElasticsearchProbe {
    /// The probe.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl ServiceProbe for ElasticsearchProbe {
    fn id(&self) -> &'static str {
        "elasticsearch"
    }

    fn default_ports(&self) -> &[u16] {
        &[9200]
    }

    fn session(&self, target: &Target) -> Box<dyn ProbeSession> {
        let host = if target.host.contains(':') {
            format!("[{}]:{}", target.host, target.port)
        } else {
            format!("{}:{}", target.host, target.port)
        };
        Box::new(EsSession {
            target: target.clone(),
            host,
            buf: Vec::new(),
            received: false,
            root: None,
            health: None,
            malformed: None,
        })
    }
}

struct EsSession {
    target: Target,
    host: String,
    buf: Vec<u8>,
    received: bool,
    root: Option<Response>,
    health: Option<Response>,
    malformed: Option<crate::Error>,
}

fn json(response: &Response) -> Option<Value> {
    serde_json::from_slice(&response.body).ok()
}

/// True when `root` is the JSON an Elasticsearch-compatible root endpoint
/// returns.
fn is_cluster_root(root: &Value) -> bool {
    root.get("version")
        .and_then(|v| v.get("number"))
        .is_some_and(Value::is_string)
        && (root.get("cluster_name").is_some() || root.get("tagline").is_some())
}

impl EsSession {
    fn store(&mut self, response: Response) -> Action {
        self.buf.clear();
        if self.root.is_none() {
            let open =
                response.status == 200 && json(&response).is_some_and(|v| is_cluster_root(&v));
            self.root = Some(response);
            if open {
                return Action::Send(get_request(&self.host, "/_cluster/health"));
            }
        } else {
            self.health = Some(response);
        }
        Action::Done
    }
}

impl ProbeSession for EsSession {
    fn start(&mut self) -> Action {
        Action::Send(get_request(&self.host, "/"))
    }

    fn on_data(&mut self, data: &[u8]) -> Action {
        self.received = true;
        self.buf.extend_from_slice(data);
        match parse_response(&self.buf, false) {
            Ok(response) => self.store(response),
            Err(e) if e.is_truncated() => Action::Receive,
            Err(e) => {
                self.malformed = Some(e);
                Action::Done
            }
        }
    }

    fn finish(&mut self, end: End) -> Result<ServiceInfo, rune_service_probe::Error> {
        const ID: &str = "elasticsearch";
        if end != End::Done && !self.buf.is_empty() {
            // A body delimited by the connection closing.
            if let Ok(response) = parse_response(&self.buf, true) {
                self.store(response);
            }
        }
        if !self.received {
            return Err(rune_service_probe::Error::no_response(ID));
        }
        let Some(root) = &self.root else {
            let reason = self
                .malformed
                .take()
                .map_or_else(|| "no HTTP response".to_owned(), |e| e.to_string());
            return Err(rune_service_probe::Error::unrecognized(ID, reason));
        };
        let mut info = ServiceInfo::new(ID).with_banner(root.status_line.clone());
        let product_header = root.header("x-elastic-product");
        match root.status {
            200 => {
                let Some(body) = json(root).filter(is_cluster_root) else {
                    return Err(rune_service_probe::Error::unrecognized(
                        ID,
                        "200 response is not an Elasticsearch root",
                    ));
                };
                info = root_details(info, &body);
                if let Some(health) = self
                    .health
                    .as_ref()
                    .filter(|h| h.status == 200)
                    .and_then(json)
                {
                    info = health_details(info, &health);
                }
                let evidence = format!(
                    "GET / -> {}; cluster_name={}",
                    root.status_line,
                    info.details
                        .get("elasticsearch.cluster_name")
                        .map_or("?", String::as_str)
                );
                info = info.with_auth(AuthRequirement::NotRequired).push_finding(
                    self.target
                        .finding(
                            "elasticsearch.unauthenticated",
                            "Elasticsearch REST API is open without authentication",
                            Severity::Critical,
                            Confidence::Certain,
                        )
                        .push_taxonomy(TaxonomyRef::cwe(306))
                        .push_evidence(Evidence::new("response", evidence))
                        .with_remediation(Remediation::new(
                            "Enable security (xpack.security.enabled: true, or the OpenSearch \
                             security plugin), require TLS, and firewall the port.",
                        )),
                );
            }
            401 | 403 => {
                info = info.with_auth(AuthRequirement::Required);
                if let Some(challenge) = root.header("www-authenticate") {
                    info = info.with_detail("elasticsearch.www_authenticate", challenge);
                }
                let es_like = product_header.is_some()
                    || root
                        .header("www-authenticate")
                        .is_some_and(|c| c.contains("realm=\"security\""))
                    || String::from_utf8_lossy(&root.body).contains("security_exception");
                if !es_like {
                    return Err(rune_service_probe::Error::unrecognized(
                        ID,
                        format!("{} without Elasticsearch markers", root.status),
                    ));
                }
                info = info.with_product(product_header.unwrap_or("Elasticsearch"));
            }
            status => {
                return Err(rune_service_probe::Error::unrecognized(
                    ID,
                    format!("unexpected status {status}"),
                ));
            }
        }
        Ok(info)
    }
}

fn str_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    path.iter()
        .try_fold(value, |v, key| v.get(key))
        .and_then(Value::as_str)
}

fn root_details(mut info: ServiceInfo, root: &Value) -> ServiceInfo {
    let distribution = str_at(root, &["version", "distribution"]);
    let product = if distribution == Some("opensearch") {
        "OpenSearch"
    } else {
        "Elasticsearch"
    };
    info = info.with_product(product);
    if let Some(number) = str_at(root, &["version", "number"]) {
        info = info.with_version(text(number.as_bytes()));
    }
    for (path, key) in [
        (&["cluster_name"][..], "elasticsearch.cluster_name"),
        (&["name"][..], "elasticsearch.node_name"),
        (&["cluster_uuid"][..], "elasticsearch.cluster_uuid"),
        (
            &["version", "lucene_version"][..],
            "elasticsearch.lucene_version",
        ),
        (
            &["version", "build_flavor"][..],
            "elasticsearch.build_flavor",
        ),
        (&["version", "build_type"][..], "elasticsearch.build_type"),
    ] {
        if let Some(value) = str_at(root, path) {
            info = info.with_detail(key, text(value.as_bytes()));
        }
    }
    info
}

fn health_details(mut info: ServiceInfo, health: &Value) -> ServiceInfo {
    if let Some(status) = health.get("status").and_then(Value::as_str) {
        info = info.with_detail("elasticsearch.health", text(status.as_bytes()));
    }
    for (key, detail) in [
        ("number_of_nodes", "elasticsearch.number_of_nodes"),
        ("number_of_data_nodes", "elasticsearch.number_of_data_nodes"),
    ] {
        if let Some(n) = health.get(key).and_then(Value::as_u64) {
            info = info.with_detail(detail, n.to_string());
        }
    }
    info
}

#[cfg(test)]
mod tests {
    use super::*;
    use rune_service_probe::{Options, simulate};

    const ROOT: &str = r#"{
  "name" : "es01",
  "cluster_name" : "docker-cluster",
  "cluster_uuid" : "x5Kj9rZ0QZ6pXq3w3qV0Cw",
  "version" : {
    "number" : "7.17.22",
    "build_flavor" : "default",
    "build_type" : "docker",
    "lucene_version" : "8.11.3"
  },
  "tagline" : "You Know, for Search"
}"#;

    fn ok(body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json; charset=UTF-8\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    fn run(replies: &[&[u8]]) -> rune_service_probe::Simulation {
        simulate(
            &ElasticsearchProbe,
            &Target::new("es.test", 9200),
            replies,
            &Options::default(),
        )
        .unwrap()
    }

    #[test]
    fn open_cluster() {
        let root = ok(ROOT);
        let health = ok(
            r#"{"cluster_name":"docker-cluster","status":"yellow","number_of_nodes":1,"number_of_data_nodes":1}"#,
        );
        let sim = run(&[&root[..40], &root[40..], &health]);
        assert_eq!(sim.sent.len(), 2);
        assert!(sim.sent[0].starts_with(b"GET / HTTP/1.1\r\nHost: es.test:9200\r\n"));
        assert!(sim.sent[1].starts_with(b"GET /_cluster/health HTTP/1.1\r\n"));
        let info = sim.result.unwrap();
        assert_eq!(info.product.as_deref(), Some("Elasticsearch"));
        assert_eq!(info.version.as_deref(), Some("7.17.22"));
        assert_eq!(info.details["elasticsearch.cluster_name"], "docker-cluster");
        assert_eq!(info.details["elasticsearch.health"], "yellow");
        assert_eq!(info.details["elasticsearch.number_of_nodes"], "1");
        assert_eq!(info.auth, AuthRequirement::NotRequired);
        assert_eq!(info.findings[0].check_id, "elasticsearch.unauthenticated");
        assert_eq!(info.findings[0].taxonomy[0].cwe_number(), Some(306));
    }

    #[test]
    fn opensearch_chunked() {
        let body = r#"{"name":"os1","cluster_name":"os","version":{"distribution":"opensearch","number":"2.15.0"},"tagline":"The OpenSearch Project: https://opensearch.org/"}"#;
        let raw = format!(
            "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n{:x}\r\n{body}\r\n0\r\n\r\n",
            body.len()
        );
        let info = run(&[raw.as_bytes()]).result.unwrap();
        assert_eq!(info.product.as_deref(), Some("OpenSearch"));
        assert_eq!(info.version.as_deref(), Some("2.15.0"));
    }

    #[test]
    fn secured_cluster() {
        let body = r#"{"error":{"root_cause":[{"type":"security_exception","reason":"missing authentication credentials for REST request [/]"}],"type":"security_exception"},"status":401}"#;
        let raw = format!(
            "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"security\" charset=\"UTF-8\"\r\nX-elastic-product: Elasticsearch\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        );
        let sim = run(&[raw.as_bytes()]);
        assert_eq!(sim.sent.len(), 1);
        let info = sim.result.unwrap();
        assert_eq!(info.auth, AuthRequirement::Required);
        assert_eq!(info.product.as_deref(), Some("Elasticsearch"));
        assert_eq!(info.findings.len(), 0);
    }

    #[test]
    fn other_http_servers_are_unrecognized() {
        for raw in [
            ok("<html>hello</html>"),
            b"HTTP/1.1 401 Unauthorized\r\ncontent-length: 0\r\n\r\n".to_vec(),
            b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n".to_vec(),
            b"\x15\x03\x03\x00\x02\x02\x46".to_vec(),
        ] {
            assert!(
                matches!(
                    run(&[&raw]).result,
                    Err(rune_service_probe::Error::Unrecognized { .. })
                ),
                "{raw:?}"
            );
        }
    }

    #[test]
    fn close_delimited_root() {
        let raw = format!("HTTP/1.0 200 OK\r\n\r\n{ROOT}");
        let sim = run(&[raw.as_bytes()]);
        assert_eq!(sim.end, End::Closed);
        assert_eq!(sim.result.unwrap().version.as_deref(), Some("7.17.22"));
    }
}

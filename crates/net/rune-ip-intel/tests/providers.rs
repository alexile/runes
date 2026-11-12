//! Each adapter against provider-shaped responses (modelled on the
//! documented examples), with no network.

#![cfg(all(
    feature = "abuseipdb",
    feature = "greynoise",
    feature = "shodan",
    feature = "censys"
))]
#![allow(clippy::unwrap_used, reason = "test helpers")]

use std::net::IpAddr;
use std::time::Duration;

use rune_ip_intel::{
    AbuseIpDb, Censys, Classification, Error, GreyNoise, HeaderValue, HttpResponse, Method,
    ReputationProvider, ShodanInternetDb, abuseipdb_category,
};
use rune_secret_ref::SecretValue;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn ok(body: &str) -> HttpResponse {
    HttpResponse::new(200).with_body(body)
}

const ABUSEIPDB: &str = r#"{
  "data": {
    "ipAddress": "118.25.6.39",
    "isPublic": true,
    "ipVersion": 4,
    "isWhitelisted": false,
    "abuseConfidenceScore": 100,
    "countryCode": "CN",
    "usageType": "Data Center/Web Hosting/Transit",
    "isp": "Tencent Cloud Computing (Beijing) Co. Ltd",
    "domain": "tencent.com",
    "hostnames": [],
    "isTor": false,
    "totalReports": 1,
    "numDistinctUsers": 1,
    "lastReportedAt": "2018-12-20T20:55:14+00:00",
    "reports": [
      {"reportedAt": "2018-12-20T20:55:14+00:00", "comment": "Dec 20 20:55:14 srv206 sshd[13937]: Invalid user oracle", "categories": [18, 22], "reporterId": 1, "reporterCountryCode": "US"},
      {"reportedAt": "2018-12-19T10:00:00+00:00", "comment": "", "categories": [22, 14, 99], "reporterId": 2, "reporterCountryCode": "DE"}
    ]
  }
}"#;

#[test]
fn abuseipdb_check() {
    let provider = AbuseIpDb::new(SecretValue::new("my-key")).with_max_age_days(30);
    let request = provider.request(ip("118.25.6.39"));
    assert_eq!(request.method, Method::Get);
    assert_eq!(
        request.url,
        "https://api.abuseipdb.com/api/v2/check?ipAddress=118.25.6.39&maxAgeInDays=30&verbose"
    );
    assert!(request.header("Key").is_some_and(HeaderValue::is_secret));

    let v = provider.parse(ip("118.25.6.39"), &ok(ABUSEIPDB)).unwrap();
    assert_eq!(v.provider, "abuseipdb");
    assert_eq!(v.classification, Classification::Malicious);
    assert_eq!(v.score, Some(100));
    assert_eq!(v.reports, Some(1));
    assert_eq!(
        v.categories,
        ["Brute-Force", "SSH", "Port Scan", "category 99"]
    );
    assert_eq!(v.country.as_deref(), Some("CN"));
    assert_eq!(
        v.organization.as_deref(),
        Some("Tencent Cloud Computing (Beijing) Co. Ltd")
    );
    assert_eq!(v.last_seen, Some(1_545_339_314));
    assert!(v.tags.contains(&"domain:tencent.com".to_owned()));
    assert_eq!(v.raw["data"]["numDistinctUsers"], 1);
    assert_eq!(abuseipdb_category(4), Some("DDoS Attack"));
}

#[test]
fn abuseipdb_thresholds_and_allowlist() {
    let provider = AbuseIpDb::new(SecretValue::new("k"));
    let body = |score: u8, white: bool| {
        format!(
            r#"{{"data":{{"abuseConfidenceScore":{score},"isWhitelisted":{white},"isTor":true,"totalReports":0}}}}"#
        )
    };
    let class = |score, white| {
        provider
            .parse(ip("192.0.2.1"), &ok(&body(score, white)))
            .unwrap()
            .classification
    };
    assert_eq!(class(0, false), Classification::Unknown);
    assert_eq!(class(25, false), Classification::Suspicious);
    assert_eq!(class(74, false), Classification::Suspicious);
    assert_eq!(class(75, false), Classification::Malicious);
    assert_eq!(class(90, true), Classification::Benign);
    let strict = AbuseIpDb::new(SecretValue::new("k")).with_thresholds(1, 10);
    let v = strict.parse(ip("192.0.2.1"), &ok(&body(5, false))).unwrap();
    assert_eq!(v.classification, Classification::Suspicious);
    assert!(v.tags.contains(&"tor".to_owned()));
}

#[test]
fn abuseipdb_errors() {
    let provider = AbuseIpDb::new(SecretValue::new("k"));
    let addr = ip("192.0.2.1");
    let body = r#"{"errors":[{"detail":"Authentication failed. Your API key is either missing, incorrect, or revoked.","status":401}]}"#;
    assert_eq!(
        provider.parse(addr, &HttpResponse::new(401).with_body(body)),
        Err(Error::Auth {
            provider: "abuseipdb",
            status: 401
        })
    );
    let limited = HttpResponse::new(429).with_header("Retry-After", "3600");
    assert_eq!(
        provider.parse(addr, &limited),
        Err(Error::RateLimited {
            provider: "abuseipdb",
            retry_after: Some(Duration::from_secs(3600))
        })
    );
    let invalid = r#"{"errors":[{"detail":"The ip address must be a valid IPv4 or IPv6 address (e.g. 8.8.8.8 or 2001:4860:4860::8888).","status":422}]}"#;
    let error = provider
        .parse(addr, &HttpResponse::new(422).with_body(invalid))
        .unwrap_err();
    assert!(matches!(error, Error::Status { status: 422, .. }));
    assert!(!error.is_retryable());
    assert!(matches!(
        provider.parse(addr, &ok("<html>")),
        Err(Error::InvalidResponse { .. })
    ));
    assert!(matches!(
        provider.parse(addr, &ok("{}")),
        Err(Error::InvalidResponse { .. })
    ));
    let server = provider.parse(addr, &HttpResponse::new(503)).unwrap_err();
    assert!(server.is_retryable());
}

#[test]
fn greynoise_community() {
    let anonymous = GreyNoise::new();
    let request = anonymous.request(ip("8.8.8.8"));
    assert_eq!(request.url, "https://api.greynoise.io/v3/community/8.8.8.8");
    assert!(request.header("key").is_none());
    let keyed = GreyNoise::new().with_key(SecretValue::new("gn"));
    assert!(
        keyed
            .request(ip("8.8.8.8"))
            .header("key")
            .is_some_and(HeaderValue::is_secret)
    );

    let riot = r#"{"ip":"8.8.8.8","noise":false,"riot":true,"classification":"benign","name":"Google Public DNS","link":"https://viz.greynoise.io/riot/8.8.8.8","last_seen":"2023-05-16","message":"Success"}"#;
    let v = anonymous.parse(ip("8.8.8.8"), &ok(riot)).unwrap();
    assert_eq!(v.classification, Classification::Benign);
    assert_eq!(v.tags, ["riot"]);
    assert_eq!(v.organization.as_deref(), Some("Google Public DNS"));
    assert_eq!(v.last_seen, Some(1_684_195_200));
    assert_eq!(v.score, None);

    let scanner = r#"{"ip":"71.6.135.131","noise":true,"riot":false,"classification":"malicious","name":"unknown","link":"https://viz.greynoise.io/ip/71.6.135.131","last_seen":"2023-05-16","message":"Success"}"#;
    let v = anonymous.parse(ip("71.6.135.131"), &ok(scanner)).unwrap();
    assert_eq!(v.classification, Classification::Malicious);
    assert_eq!(v.tags, ["scanner"]);
    assert_eq!(v.organization, None);

    let unseen = r#"{"ip":"1.2.3.4","noise":false,"riot":false,"message":"IP not observed scanning the internet or contained in RIOT data set."}"#;
    let v = anonymous
        .parse(ip("1.2.3.4"), &HttpResponse::new(404).with_body(unseen))
        .unwrap();
    assert_eq!(v.classification, Classification::Unknown);
    assert_eq!(v.tags, [] as [std::string::String; 0]);
    assert!(
        anonymous
            .parse(ip("1.2.3.4"), &HttpResponse::new(404))
            .is_ok()
    );

    assert!(matches!(
        anonymous.parse(ip("1.2.3.4"), &ok("[1,2]")),
        Err(Error::InvalidResponse { .. })
    ));
    assert!(matches!(
        anonymous.parse(ip("1.2.3.4"), &HttpResponse::new(429)),
        Err(Error::RateLimited {
            retry_after: None,
            ..
        })
    ));
}

#[test]
fn shodan_internetdb() {
    let provider = ShodanInternetDb::new().with_base_url("http://localhost:8080/");
    assert_eq!(provider.request(ip("::1")).url, "http://localhost:8080/::1");
    assert!(
        provider
            .request(ip("1.1.1.1"))
            .headers
            .iter()
            .all(|(_, v)| !v.is_secret())
    );

    let body = r#"{"cpes":["cpe:/a:openbsd:openssh:7.4","cpe:/a:nginx:nginx"],"hostnames":["scanme.example"],"ip":"45.33.32.156","ports":[22,80,9929,31337,70000],"tags":["cloud","c2"],"vulns":["CVE-2016-20012","CVE-2018-15473"]}"#;
    let v = provider.parse(ip("45.33.32.156"), &ok(body)).unwrap();
    assert_eq!(v.open_ports, [22, 80, 9929, 31337]);
    assert_eq!(v.hostnames, ["scanme.example"]);
    assert_eq!(v.vulns, ["CVE-2016-20012", "CVE-2018-15473"]);
    assert_eq!(v.classification, Classification::Malicious);
    assert_eq!(
        v.tags,
        [
            "cloud",
            "c2",
            "cpe:/a:openbsd:openssh:7.4",
            "cpe:/a:nginx:nginx"
        ]
    );

    let tor =
        r#"{"cpes":[],"hostnames":[],"ip":"1.1.1.1","ports":[443],"tags":["Tor"],"vulns":[]}"#;
    let v = provider.parse(ip("1.1.1.1"), &ok(tor)).unwrap();
    assert_eq!(v.classification, Classification::Suspicious);

    let missing = HttpResponse::new(404).with_body(r#"{"detail":"No information available"}"#);
    let v = provider.parse(ip("192.0.2.9"), &missing).unwrap();
    assert_eq!(v.classification, Classification::Unknown);
    assert_eq!(v.open_ports, [] as [u16; 0]);
    assert_eq!(v.raw["detail"], "No information available");
}

#[test]
fn censys_hosts() {
    let provider = Censys::new(&SecretValue::new("id"), &SecretValue::new("secret"));
    let request = provider.request(ip("8.8.8.8"));
    assert_eq!(request.url, "https://search.censys.io/api/v2/hosts/8.8.8.8");
    // base64("id:secret")
    assert_eq!(
        request.header("authorization").map(HeaderValue::expose),
        Some("Basic aWQ6c2VjcmV0")
    );
    assert!(!format!("{request:?}").contains("aWQ6c2VjcmV0"));

    let body = r#"{
      "code": 200, "status": "OK",
      "result": {
        "ip": "8.8.8.8",
        "services": [
          {"port": 53, "service_name": "DNS", "transport_protocol": "UDP"},
          {"port": 443, "service_name": "HTTP", "transport_protocol": "TCP"},
          {"port": 443, "service_name": "HTTP", "transport_protocol": "QUIC"}
        ],
        "location": {"continent": "North America", "country": "United States", "country_code": "US"},
        "autonomous_system": {"asn": 15169, "description": "GOOGLE", "bgp_prefix": "8.8.8.0/24", "name": "GOOGLE", "country_code": "US"},
        "dns": {"reverse_dns": {"names": ["dns.google"]}},
        "labels": ["open-resolver"],
        "last_updated_at": "2023-04-04T10:04:41.123Z"
      }
    }"#;
    let v = provider.parse(ip("8.8.8.8"), &ok(body)).unwrap();
    assert_eq!(v.open_ports, [53, 443]);
    assert_eq!(v.tags, ["open-resolver", "service:dns", "service:http"]);
    assert_eq!(v.asn, Some(15169));
    assert_eq!(v.organization.as_deref(), Some("GOOGLE"));
    assert_eq!(v.country.as_deref(), Some("US"));
    assert_eq!(v.hostnames, ["dns.google"]);
    assert_eq!(v.last_seen, Some(1_680_602_681));
    assert_eq!(v.classification, Classification::Unknown);

    assert_eq!(
        provider.parse(ip("8.8.8.8"), &HttpResponse::new(401)),
        Err(Error::Auth {
            provider: "censys",
            status: 401
        })
    );
    assert!(
        provider
            .parse(ip("8.8.8.8"), &HttpResponse::new(404))
            .is_ok()
    );
    assert!(matches!(
        provider.parse(ip("8.8.8.8"), &ok(r#"{"code":200}"#)),
        Err(Error::InvalidResponse { .. })
    ));
}

#[test]
fn check_goes_through_the_transport() {
    let provider = ShodanInternetDb::new();
    let transport = |request: &rune_ip_intel::HttpRequest| {
        assert_eq!(request.url, "https://internetdb.shodan.io/9.9.9.9");
        Ok(ok(
            r#"{"ports":[53],"tags":[],"cpes":[],"hostnames":[],"vulns":[]}"#,
        ))
    };
    assert_eq!(
        provider
            .check(ip("9.9.9.9"), &transport)
            .unwrap()
            .open_ports,
        [53]
    );

    let down = |_: &rune_ip_intel::HttpRequest| {
        Err(rune_ip_intel::TransportError::retryable(
            "connection refused",
        ))
    };
    let error = provider.check(ip("9.9.9.9"), &down).unwrap_err();
    assert!(error.is_retryable());
    assert_eq!(error.to_string(), "transport error: connection refused");
}

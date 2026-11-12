//! Captured IANA bootstrap files and RDAP responses (Verisign, ARIN, RIPE)
//! parsed end to end. See `tests/fixtures/`.
#![allow(
    clippy::unwrap_used,
    reason = "test helpers outside #[test] fns: any failure fails the test"
)]

use rune_rdap::bootstrap::{Bootstrap, Registry, RegistryKind};
use rune_rdap::model::{EventAction, Role, Status};
use rune_rdap::response::{Response, interpret};
use rune_rdap::{Error, Object, Query, parse_object};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn iana() -> Bootstrap {
    let mut b = Bootstrap::new();
    for (kind, file) in [
        (RegistryKind::Dns, "bootstrap-dns.json"),
        (RegistryKind::Ipv4, "bootstrap-ipv4.json"),
        (RegistryKind::Ipv6, "bootstrap-ipv6.json"),
        (RegistryKind::Asn, "bootstrap-asn.json"),
        (RegistryKind::ObjectTags, "bootstrap-object-tags.json"),
    ] {
        let registry = Registry::parse(kind, &fixture(file)).unwrap();
        assert_eq!(registry.version(), "1.0");
        assert!(registry.publication().is_some());
        assert_ne!(registry.services().len(), 0);
        b.insert(registry);
    }
    b
}

fn first_url(b: &Bootstrap, q: &str) -> String {
    b.urls(&Query::parse(q).unwrap()).unwrap().remove(0)
}

#[test]
fn routes_with_iana_registries() {
    let b = iana();
    assert_eq!(
        first_url(&b, "example.com"),
        "https://rdap.verisign.com/com/v1/domain/example.com"
    );
    assert_eq!(
        first_url(&b, "bbc.co.uk"),
        "https://rdap.nominet.uk/uk/domain/bbc.co.uk"
    );
    assert_eq!(
        first_url(&b, "8.8.8.8"),
        "https://rdap.arin.net/registry/ip/8.8.8.8"
    );
    assert_eq!(
        first_url(&b, "193.0.6.139"),
        "https://rdap.db.ripe.net/ip/193.0.6.139"
    );
    assert_eq!(
        first_url(&b, "2001:4200::1"),
        "https://rdap.afrinic.net/rdap/ip/2001:4200::1"
    );
    assert_eq!(
        first_url(&b, "AS15169"),
        "https://rdap.arin.net/registry/autnum/15169"
    );
    assert_eq!(
        first_url(&b, "ZG39-ARIN"),
        "https://rdap.arin.net/registry/entity/ZG39-ARIN"
    );
    // https is preferred over the http mirror the file also lists.
    let afrinic = b.base_urls(&Query::parse("41.0.0.1").unwrap()).unwrap();
    assert_eq!(
        afrinic,
        [
            "https://rdap.afrinic.net/rdap/",
            "http://rdap.afrinic.net/rdap/"
        ]
    );
    // Unallocated or unknown.
    assert!(matches!(
        b.urls(&Query::parse("example.invalid").unwrap()),
        Err(Error::NoService { .. })
    ));
    assert!(matches!(
        b.urls(&Query::parse("10.0.0.1").unwrap()),
        Err(Error::NoService { .. })
    ));
}

#[test]
fn verisign_domain() {
    let obj = parse_object(&fixture("domain-example.com.json")).unwrap();
    let d = obj.as_domain().unwrap();
    assert_eq!(d.name(), Some("EXAMPLE.COM"));
    assert_eq!(d.handle.as_deref(), Some("2336799_DOMAIN_COM-VRSN"));
    assert_eq!(
        d.registrar_name(),
        Some("RESERVED-Internet Assigned Numbers Authority")
    );
    assert_eq!(d.registrar_iana_id(), Some("376"));
    assert_eq!(d.registration(), Some("1995-08-14T04:00:00Z"));
    assert_eq!(d.expiration(), Some("2027-08-13T04:00:00Z"));
    assert_eq!(d.last_changed(), Some("2026-08-14T08:01:43Z"));
    assert!(
        d.event_date(&EventAction::LastUpdateOfRdapDatabase)
            .is_some()
    );
    assert_eq!(
        d.nameserver_names().collect::<Vec<_>>(),
        ["ELLIOTT.NS.CLOUDFLARE.COM", "HERA.NS.CLOUDFLARE.COM"]
    );
    assert_eq!(
        d.status,
        [
            Status::ClientDeleteProhibited,
            Status::ClientTransferProhibited,
            Status::ClientUpdateProhibited
        ]
    );
    let dns = d.secure_dns.as_ref().unwrap();
    assert_eq!(dns.delegation_signed, Some(true));
    assert_eq!(dns.ds_data[0].key_tag, Some(2371));
    assert!(
        d.notices
            .iter()
            .any(|n| n.title.as_deref() == Some("Terms of Service"))
    );
    // The registrar's abuse contact is redacted to empty strings.
    let abuse = d.entity_with_role(&Role::Abuse).unwrap();
    let contact = abuse.contact.as_ref().unwrap();
    assert!(contact.emails.is_empty() && contact.phones.is_empty());
    assert_eq!(d.abuse_email(), None);
}

#[test]
fn arin_ip_network() {
    let obj = parse_object(&fixture("ip-arin-8.8.8.8.json")).unwrap();
    assert_eq!(obj.class_name(), "ip network");
    let n = obj.as_ip_network().unwrap();
    assert_eq!(n.start_address.as_deref(), Some("8.8.8.0"));
    assert_eq!(n.end_address.as_deref(), Some("8.8.8.255"));
    assert_eq!(n.ip_version.as_deref(), Some("v4"));
    assert_eq!(n.cidrs[0].prefix, "8.8.8.0");
    assert_eq!(n.cidrs[0].length, 24);
    assert_eq!(n.port43.as_deref(), Some("whois.arin.net"));
    assert_eq!(n.abuse_email(), Some("network-abuse@google.com"));
    let abuse = n.entity_with_role(&Role::Abuse).unwrap();
    let contact = abuse.contact.as_ref().unwrap();
    assert_eq!(contact.org.as_deref(), Some("Google Inc."));
    assert_eq!(contact.phones, ["+1-650-253-0000"]);
    assert!(
        contact
            .address
            .as_deref()
            .unwrap()
            .starts_with("1600 Amphitheatre Parkway")
    );
    assert!(n.all_entities().len() >= 2);
}

#[test]
fn ripe_ip_network() {
    let obj = parse_object(&fixture("ip-ripe-193.0.6.139.json")).unwrap();
    let n = obj.as_ip_network().unwrap();
    assert_eq!(n.country.as_deref(), Some("NL"));
    assert_eq!(n.cidrs[0].prefix, "193.0.0.0");
    assert_eq!(n.cidrs[0].length, 21);
    assert_eq!(n.port43.as_deref(), Some("whois.ripe.net"));
}

#[test]
fn arin_autnum() {
    let obj = parse_object(&fixture("autnum-arin-15169.json")).unwrap();
    let a = obj.as_autnum().unwrap();
    assert_eq!(a.handle.as_deref(), Some("AS15169"));
    assert_eq!(a.start_autnum, Some(15_169));
    assert_eq!(a.end_autnum, Some(15_169));
    assert_eq!(a.name.as_deref(), Some("GOOGLE"));
    assert!(a.registration().is_some());
    assert!(a.entity_with_role(&Role::Registrant).is_some());
}

#[test]
fn verisign_nameserver() {
    let obj = parse_object(&fixture("nameserver-a.iana-servers.net.json")).unwrap();
    let ns = obj.as_nameserver().unwrap();
    assert_eq!(ns.name(), Some("A.IANA-SERVERS.NET"));
    let ips = ns.ip_addresses.as_ref().unwrap();
    assert_eq!(ips.v4, ["199.43.135.53"]);
    assert_eq!(ips.v6, ["2001:500:8F:0:0:0:0:53"]);
}

#[test]
fn arin_error_response() {
    let r = Response::new(400, fixture("error-arin-400.json"));
    match interpret(&r) {
        Err(Error::Server {
            status: 400,
            error_code: Some(400),
            title,
            description,
        }) => {
            assert_eq!(title.as_deref(), Some("BAD REQUEST"));
            assert_eq!(description[0], "Your request is bad.");
        }
        other => panic!("{other:?}"),
    }
    // An error body is not an object.
    assert!(parse_object(&fixture("error-arin-400.json")).is_err());
}

#[test]
fn every_object_fixture_parses() {
    for (file, class) in [
        ("domain-example.com.json", "domain"),
        ("ip-arin-8.8.8.8.json", "ip network"),
        ("ip-ripe-193.0.6.139.json", "ip network"),
        ("autnum-arin-15169.json", "autnum"),
        ("nameserver-a.iana-servers.net.json", "nameserver"),
    ] {
        let obj: Object = parse_object(&fixture(file)).unwrap();
        assert_eq!(obj.class_name(), class, "{file}");
        assert!(!obj.events().is_empty(), "{file}");
    }
}

//! Property tests: parsers never panic, and canonical forms round-trip.

use std::net::{Ipv4Addr, Ipv6Addr};

use proptest::prelude::*;
use rune_dns_records::bimi::Bimi;
use rune_dns_records::caa::CaaRecord;
use rune_dns_records::dkim::DkimKey;
use rune_dns_records::dmarc::Dmarc;
use rune_dns_records::mta_sts::{MtaStsPolicy, MtaStsRecord};
use rune_dns_records::spf::Spf;
use rune_dns_records::tls_rpt::TlsRpt;
use rune_dns_records::tlsa::TlsaRecord;
use rune_dns_wire::{Caa, Tlsa};

fn domain() -> impl Strategy<Value = String> {
    ("[a-z0-9_]{1,10}", "[a-z][a-z0-9]{0,5}").prop_map(|(a, b)| format!("{a}.{b}"))
}

fn qualifier() -> impl Strategy<Value = &'static str> {
    prop::sample::select(vec!["", "+", "-", "~", "?"])
}

fn term() -> impl Strategy<Value = String> {
    prop_oneof![
        (qualifier(), domain()).prop_map(|(q, d)| format!("{q}include:{d}")),
        (
            qualifier(),
            prop::option::of(domain()),
            prop::option::of(0u8..=32),
            prop::option::of(0u8..=128)
        )
            .prop_map(|(q, d, v4, v6)| {
                format!(
                    "{q}a{}{}{}",
                    d.map(|d| format!(":{d}")).unwrap_or_default(),
                    v4.map(|v| format!("/{v}")).unwrap_or_default(),
                    v6.map(|v| format!("//{v}")).unwrap_or_default()
                )
            }),
        (qualifier(), any::<u32>(), prop::option::of(0u8..=32)).prop_map(|(q, a, p)| format!(
            "{q}ip4:{}{}",
            Ipv4Addr::from(a),
            p.map(|p| format!("/{p}")).unwrap_or_default()
        )),
        (qualifier(), any::<u128>(), prop::option::of(0u8..=128)).prop_map(|(q, a, p)| format!(
            "{q}ip6:{}{}",
            Ipv6Addr::from(a),
            p.map(|p| format!("/{p}")).unwrap_or_default()
        )),
        (qualifier(), domain()).prop_map(|(q, d)| format!("{q}exists:%{{i}}.{d}")),
        qualifier().prop_map(|q| format!("{q}mx")),
        qualifier().prop_map(|q| format!("{q}all")),
        domain().prop_map(|d| format!("x-ext={d}")),
    ]
}

proptest! {
    #[test]
    fn parsers_never_panic(text in "\\PC{0,200}") {
        let _ = Spf::parse(&text);
        let _ = DkimKey::parse(&text);
        let _ = Dmarc::parse(&text);
        let _ = MtaStsRecord::parse(&text);
        let _ = MtaStsPolicy::parse(&text);
        let _ = TlsRpt::parse(&text);
        let _ = Bimi::parse(&text);
        let _ = text.parse::<CaaRecord>();
        let _ = text.parse::<TlsaRecord>();
    }

    #[test]
    fn prefixed_text_never_panics(
        prefix in prop::sample::select(vec!["v=spf1 ", "v=DMARC1; ", "v=DKIM1; ", "v=STSv1; ", "v=TLSRPTv1; ", "v=BIMI1; ", "version: STSv1\n", "0 issue ", "3 1 1 "]),
        rest in "[ -~]{0,120}",
    ) {
        let text = format!("{prefix}{rest}");
        if let Ok(spf) = Spf::parse(&text) {
            let _ = spf.issues();
            let _ = spf.count_lookups("example.com", |_| Some(text.clone()));
        }
        if let Ok(d) = Dmarc::parse(&text) {
            prop_assert_eq!(Dmarc::parse(&d.to_string()), Ok(d));
        }
        if let Ok(k) = DkimKey::parse(&text) {
            let _ = k.issues();
        }
        if let Ok(p) = MtaStsPolicy::parse(&text) {
            prop_assert_eq!(MtaStsPolicy::parse(&p.to_string()), Ok(p));
        }
        if let Ok(c) = text.parse::<CaaRecord>() {
            prop_assert_eq!(c.to_string().parse::<CaaRecord>(), Ok(c));
        }
    }

    #[test]
    fn spf_round_trips(terms in prop::collection::vec(term(), 0..12)) {
        let text = format!("v=spf1 {}", terms.join(" "));
        let spf = Spf::parse(&text).map_err(|e| TestCaseError::fail(format!("{text}: {e}")))?;
        prop_assert_eq!(spf.terms.len(), terms.len());
        prop_assert_eq!(Spf::parse(&spf.to_string()), Ok(spf.clone()));
        let _ = spf.issues();
    }

    #[test]
    fn caa_wire_values_round_trip(flags: u8, tag in "[a-zA-Z0-9]{1,15}", value in prop::collection::vec(any::<u8>(), 0..64)) {
        let caa = Caa { flags, tag, value };
        if let Ok(record) = CaaRecord::from_rdata(&caa) {
            prop_assert_eq!(record.to_string().parse::<CaaRecord>(), Ok(record.clone()));
            prop_assert_eq!(CaaRecord::from_rdata(&record.to_rdata()), Ok(record));
        }
        let _ = rune_dns_records::caa::permits(std::slice::from_ref(&caa), "ca.example", true);
        let _ = rune_dns_records::caa::issues(&[caa]);
    }

    #[test]
    fn tlsa_round_trips(usage: u8, selector: u8, matching_type: u8, data in prop::collection::vec(any::<u8>(), 0..80)) {
        let tlsa = Tlsa { usage, selector, matching_type, data };
        if let Ok(record) = TlsaRecord::from_rdata(&tlsa) {
            prop_assert_eq!(record.to_string().parse::<TlsaRecord>(), Ok(record.clone()));
            prop_assert_eq!(record.to_rdata(), tlsa);
        }
    }
}

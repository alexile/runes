//! Round trips on real zone files and reassembly of a captured AXFR stream.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "helpers outside #[test] functions fail the test on bad input"
)]

use std::collections::HashSet;

use rune_dns_wire::{Message, Name, RData, Record, RecordType};
use rune_dns_zone::{
    Axfr, Error, ParseOptions, Status, TcpFrames, Zone, parse, parse_with_includes,
    record_type_name,
};

const ZONETRANSFER_ME: &str = include_str!("fixtures/zonetransfer.me.zone");
const EXAMPLE_COM: &str = include_str!("fixtures/example.com.zone");
const LAN_INC: &str = include_str!("fixtures/lan.inc");
/// The raw DNS-over-TCP stream of `dig axfr zonetransfer.me
/// @nsztm1.digi.ninja`: length-prefixed messages, captured 2026-11-11.
const AXFR_CAPTURE: &[u8] = include_bytes!("fixtures/axfr-zonetransfer-me.bin");

fn name(text: &str) -> Name {
    Name::from_ascii(text).unwrap()
}

fn round_trip(zone: &Zone) {
    let text = zone.to_master_file();
    let again =
        parse(&text, &ParseOptions::default()).unwrap_or_else(|error| panic!("{error}\n{text}"));
    assert_eq!(&again, zone, "{text}");
    assert_eq!(again.to_master_file(), text, "writing is not stable");
}

fn example_com() -> Zone {
    parse_with_includes(EXAMPLE_COM, &ParseOptions::default(), |path| {
        (path == "lan.inc")
            .then(|| LAN_INC.to_owned())
            .ok_or_else(|| format!("{path}: not found"))
    })
    .unwrap()
}

#[test]
fn zonetransfer_me_round_trips() {
    let zone = parse(ZONETRANSFER_ME, &ParseOptions::default()).unwrap();
    assert_eq!(zone.records.len(), 51);
    assert_eq!(zone.origin(), Some(&name("zonetransfer.me")));
    assert_eq!(zone.soa().map(|soa| soa.serial), Some(2_019_100_801));

    let types: HashSet<String> = zone
        .records
        .iter()
        .map(|record| record_type_name(record.rtype()))
        .collect();
    for expected in [
        "SOA", "NS", "MX", "A", "AAAA", "TXT", "CNAME", "SRV", "PTR", "HINFO", "AFSDB", "RP",
        "LOC", "NAPTR", "CERT", "DNSKEY",
    ] {
        assert!(types.contains(expected), "{expected} missing");
    }

    // The tricky TXT records survive with their content intact.
    let txt = |owner: &str| {
        zone.records
            .iter()
            .find(|record| record.name == name(owner))
            .map(|record| record.data.clone())
    };
    assert_eq!(
        txt("cmdexec.zonetransfer.me"),
        Some(RData::Txt(vec![b"; ls".to_vec()]))
    );
    assert_eq!(
        txt("sshock.zonetransfer.me"),
        Some(RData::Txt(vec![b"() { :]}; echo ShellShocked".to_vec()]))
    );
    round_trip(&zone);
}

#[test]
fn example_com_features() {
    let zone = example_com();
    round_trip(&zone);

    let find = |owner: &str, rtype: RecordType| -> Vec<&Record> {
        zone.records
            .iter()
            .filter(|record| record.name == name(owner) && record.rtype() == rtype)
            .collect()
    };
    let soa = zone.soa().unwrap();
    assert_eq!(
        (soa.serial, soa.refresh, soa.retry, soa.expire, soa.minimum),
        (2_026_111_101, 7_200, 900, 1_209_600, 300)
    );
    assert_eq!(soa.rname, name("hostmaster.example.com"));
    // `$TTL 1h` applies, an explicit TTL overrides it, in either position.
    assert_eq!(find("example.com", RecordType::NS)[0].ttl, 3600);
    assert_eq!(find("example.com", RecordType::DNSKEY)[0].ttl, 86_400);
    assert_eq!(find("mail.example.com", RecordType::A)[0].ttl, 300);
    assert_eq!(find("mail.example.com", RecordType::AAAA)[0].ttl, 300);
    // The RRSIG has a blank owner after the DNSKEY line, so it is the apex.
    let RData::Rrsig(sig) = &find("example.com", RecordType::RRSIG)[0].data else {
        panic!("no RRSIG")
    };
    assert_eq!(
        (sig.expiration, sig.inception),
        (1_796_947_200, 1_794_355_200)
    );
    assert_eq!(
        find("www.example.com", RecordType::CNAME)[0].data,
        RData::Cname(name("example.com"))
    );
    assert_eq!(
        find("1.2.0.192.in-addr.arpa", RecordType::PTR)[0].data,
        RData::Ptr(name("www.example.com"))
    );
    assert_eq!(
        find("legacy.example.com", RecordType(65_280))[0].data,
        RData::Unknown {
            rtype: RecordType(65_280),
            data: vec![10, 0, 0, 1],
        }
    );
    // `$INCLUDE lan.inc lan` and the origin restored after it.
    assert_eq!(find("printer.lan.example.com", RecordType::A).len(), 1);
    assert_eq!(find("nas.lan.example.com", RecordType::TXT).len(), 1);
    assert_eq!(
        find("after-include.example.com", RecordType::TXT)[0].data,
        RData::Txt(vec![
            b"origin restored".to_vec(),
            b"second string".to_vec(),
            b"\"unquoted\"".to_vec(),
        ])
    );
    assert_eq!(zone.records.len(), 30);
}

#[test]
fn include_needs_a_loader() {
    assert!(matches!(
        parse(EXAMPLE_COM, &ParseOptions::default()),
        Err(Error::Include { line: 48, .. })
    ));
}

#[test]
fn captured_axfr_reassembles_to_the_zone_file() {
    let mut frames = TcpFrames::new();
    // Feed the stream in awkward pieces, as a socket would.
    for chunk in AXFR_CAPTURE.chunks(97) {
        frames.push(chunk);
    }
    let mut axfr = Axfr::new(name("zonetransfer.me")).with_id(0x4a7f);
    let mut status = Status::More;
    let mut messages = 0;
    while let Some(frame) = frames.next_frame() {
        status = axfr.push_bytes(&frame).unwrap();
        messages += 1;
    }
    assert_eq!(messages, 1);
    assert_eq!(status, Status::Done);
    assert_eq!(frames.buffered(), 0);
    let transferred = axfr.finish().unwrap();

    // The transfer and dig's text rendering of it agree record for record.
    let from_file = parse(ZONETRANSFER_ME, &ParseOptions::default()).unwrap();
    assert_eq!(transferred, from_file);
    round_trip(&transferred);
}

#[test]
fn captured_axfr_split_over_messages() {
    // Re-send the captured records one per message (the old BIND
    // "one-answer" format) and in batches of 7.
    let mut frames = TcpFrames::new();
    frames.push(AXFR_CAPTURE);
    let message = Message::decode(&frames.next_frame().unwrap()).unwrap();
    for batch in [1, 7] {
        let mut axfr = Axfr::new(name("ZoneTransfer.ME"));
        let mut status = Status::More;
        for chunk in message.answers.chunks(batch) {
            let mut part = message.clone();
            part.answers = chunk.to_vec();
            let bytes = TcpFrames::frame(&part.encode().unwrap()).unwrap();
            let mut stream = TcpFrames::new();
            stream.push(&bytes);
            status = axfr.push_bytes(&stream.next_frame().unwrap()).unwrap();
        }
        assert_eq!(status, Status::Done);
        assert_eq!(axfr.finish().unwrap().records.len(), 51);
    }
}

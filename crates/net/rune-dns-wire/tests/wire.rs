//! Hand-built packets: hostile input the decoder must reject, known-answer
//! encodings, the builders and truncation.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "helpers outside #[test] functions fail the test on bad input"
)]

use std::net::Ipv4Addr;

use rune_dns_wire::{
    Class, Edns, EdnsOption, Error, Header, MAX_NAME_LEN, Message, Name, Opcode, Question, RData,
    Rcode, Record, RecordType, Rrsig, Srv,
};

fn name(text: &str) -> Name {
    text.parse().unwrap()
}

/// A header with the given counts and flags.
fn header(flags: u16, counts: [u16; 4]) -> Vec<u8> {
    let mut out = vec![0xAB, 0xCD];
    out.extend_from_slice(&flags.to_be_bytes());
    for count in counts {
        out.extend_from_slice(&count.to_be_bytes());
    }
    out
}

/// One question whose name is `name_bytes`, type A, class IN.
fn with_question(name_bytes: &[u8]) -> Vec<u8> {
    let mut out = header(0, [1, 0, 0, 0]);
    out.extend_from_slice(name_bytes);
    out.extend_from_slice(&[0, 1, 0, 1]);
    out
}

/// A compression pointer to `offset`.
fn pointer(offset: usize) -> [u8; 2] {
    (0xC000 | u16::try_from(offset).unwrap()).to_be_bytes()
}

// --- Hostile input -------------------------------------------------------

#[test]
fn rejects_short_header() {
    assert_eq!(Message::decode(&[]), Err(Error::Truncated { offset: 0 }));
    assert!(matches!(
        Message::decode(&[0; 11]),
        Err(Error::Truncated { .. })
    ));
    assert!(Message::decode(&[0; 12]).is_ok());
}

#[test]
fn rejects_self_pointer() {
    // The question name is a pointer to itself, at offset 12.
    assert_eq!(
        Message::decode(&with_question(&[0xC0, 12])),
        Err(Error::BadPointer {
            offset: 12,
            target: 12
        })
    );
}

#[test]
fn rejects_forward_pointer() {
    assert_eq!(
        Message::decode(&with_question(&[0xC0, 14, 0])),
        Err(Error::BadPointer {
            offset: 12,
            target: 14
        })
    );
}

#[test]
fn rejects_pointer_into_header() {
    assert_eq!(
        Message::decode(&with_question(&[1, b'a', 0xC0, 2])),
        Err(Error::BadPointer {
            offset: 14,
            target: 2
        })
    );
}

#[test]
fn rejects_two_step_loop() {
    // Question 1 at 12: "a" then a pointer to 19. Question 2 at 19: a
    // pointer back to 12. Following them would loop 12 -> 19 -> 12; the
    // forward pointer is rejected first.
    let mut packet = header(0, [2, 0, 0, 0]);
    packet.extend_from_slice(&[1, b'a', 0xC0, 19, 0, 1, 0, 1]);
    packet.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1]);
    assert!(matches!(
        Message::decode(&packet),
        Err(Error::BadPointer { target: 19, .. })
    ));
}

#[test]
fn rejects_loop_through_earlier_run() {
    // A pointer to its own run of labels would loop.
    let mut packet = header(0, [2, 0, 0, 0]);
    // Question 1 at 12: "a" + root, A IN.
    packet.extend_from_slice(&[1, b'a', 0, 0, 1, 0, 1]);
    // Question 2 at 19: label "b" then pointer to 21, which is the pointer
    // itself's position: target 21 >= run start 19.
    packet.extend_from_slice(&[1, b'b', 0xC0, 21, 0, 1, 0, 1]);
    assert_eq!(
        Message::decode(&packet),
        Err(Error::BadPointer {
            offset: 21,
            target: 21
        })
    );
}

#[test]
fn bounds_pointer_chains() {
    // 200 questions; each name is a pointer to the previous question's
    // name, the first one is the root. Every jump goes backwards, but the
    // last name needs 200 hops: more than the 128 any valid name needs.
    let mut packet = header(0, [201, 0, 0, 0]);
    let mut offsets = Vec::new();
    // Question 0: root.
    offsets.push(packet.len());
    packet.extend_from_slice(&[0, 0, 1, 0, 1]);
    for _ in 0..200 {
        let previous = *offsets.last().unwrap();
        offsets.push(packet.len());
        packet.extend_from_slice(&pointer(previous));
        packet.extend_from_slice(&[0, 1, 0, 1]);
    }
    assert!(matches!(
        Message::decode(&packet),
        Err(Error::TooManyPointers { .. })
    ));
    // 128 hops are still fine.
    let mut packet = header(0, [129, 0, 0, 0]);
    let mut previous = packet.len();
    packet.extend_from_slice(&[0, 0, 1, 0, 1]);
    for _ in 0..128 {
        let here = packet.len();
        packet.extend_from_slice(&pointer(previous));
        packet.extend_from_slice(&[0, 1, 0, 1]);
        previous = here;
    }
    let message = Message::decode(&packet).unwrap();
    assert!(message.questions.iter().all(|q| q.name.is_root()));
}

#[test]
fn rejects_oversize_name_built_from_pointers() {
    // Question 1: a 63-octet label + root (65 octets of wire name).
    // Questions 2..: one more 63-octet label + pointer to the previous one.
    // The fourth one reaches 4 * 64 + 1 = 257 octets.
    let label = [b'x'; 63];
    let mut packet = header(0, [4, 0, 0, 0]);
    let mut previous = packet.len();
    packet.push(63);
    packet.extend_from_slice(&label);
    packet.extend_from_slice(&[0, 0, 1, 0, 1]);
    for _ in 0..3 {
        let here = packet.len();
        packet.push(63);
        packet.extend_from_slice(&label);
        packet.extend_from_slice(&pointer(previous));
        packet.extend_from_slice(&[0, 1, 0, 1]);
        previous = here;
    }
    assert_eq!(Message::decode(&packet), Err(Error::NameTooLong));
}

#[test]
fn accepts_longest_name() {
    let longest = format!("{0}.{0}.{0}.{1}", "a".repeat(63), "b".repeat(61));
    let query = Message::query(1, Question::new(name(&longest), RecordType::A));
    let decoded = Message::decode(&query.encode().unwrap()).unwrap();
    assert_eq!(decoded.questions[0].name.wire_len(), MAX_NAME_LEN);
}

#[test]
fn rejects_reserved_label_types() {
    for byte in [0x40, 0x41, 0x80, 0xBF] {
        assert_eq!(
            Message::decode(&with_question(&[byte, 0])),
            Err(Error::BadLabelType { offset: 12, byte })
        );
    }
}

#[test]
fn rejects_label_running_off_the_end() {
    assert!(matches!(
        Message::decode(&with_question(&[5, b'a', b'b'])),
        Err(Error::Truncated { .. })
    ));
}

#[test]
fn rejects_trailing_data() {
    let mut packet = Message::query(7, Question::new(name("a.example"), RecordType::A))
        .encode()
        .unwrap();
    let len = packet.len();
    packet.push(0);
    assert_eq!(
        Message::decode(&packet),
        Err(Error::TrailingData {
            offset: len,
            len: 1
        })
    );
}

#[test]
fn huge_counts_do_not_allocate() {
    // 65535 of everything, no data: fails fast on the first question.
    let packet = header(0, [u16::MAX; 4]);
    assert!(matches!(
        Message::decode(&packet),
        Err(Error::Truncated { .. })
    ));
}

/// A response to `a.example A` with one answer record of `rtype` and the
/// given RDATA.
fn answer_packet(rtype: RecordType, rdata: &[u8]) -> Vec<u8> {
    let mut packet = header(0x8000, [1, 1, 0, 0]);
    packet.extend_from_slice(b"\x01a\x07example\x00\x00\x01\x00\x01");
    packet.extend_from_slice(&[0xC0, 12]);
    packet.extend_from_slice(&rtype.0.to_be_bytes());
    packet.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
    packet.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
    packet.extend_from_slice(rdata);
    packet
}

#[test]
fn rejects_rdata_of_the_wrong_length() {
    for (rtype, rdata) in [
        (RecordType::A, &[1, 2, 3][..]),
        (RecordType::A, &[1, 2, 3, 4, 5][..]),
        (RecordType::AAAA, &[0; 15][..]),
        (RecordType::MX, &[0, 10, 0, 9][..]),
        (RecordType::CNAME, &[0, 0][..]),
        (RecordType::SRV, &[0, 1, 0, 1, 0][..]),
        (RecordType::TXT, &[5, b'a'][..]),
        (RecordType::DS, &[0, 1, 13][..]),
    ] {
        let result = Message::decode(&answer_packet(rtype, rdata));
        assert!(
            matches!(
                result,
                Err(Error::Truncated { .. } | Error::InvalidRdata { .. })
            ),
            "{rtype} {rdata:?}: {result:?}"
        );
    }
}

#[test]
fn rdata_names_may_not_run_past_the_rdata() {
    // CNAME RDATA of length 2 holding the start of a longer name: the
    // decoder must not read the label out of the following bytes.
    let mut packet = answer_packet(RecordType::CNAME, &[3, b'f']);
    packet.extend_from_slice(b"oo\x00");
    assert!(matches!(
        Message::decode(&packet),
        Err(Error::Truncated { .. })
    ));
}

#[test]
fn rdata_names_may_point_backwards() {
    // CNAME RDATA: label "www" then a pointer to the question name.
    let message = Message::decode(&answer_packet(
        RecordType::CNAME,
        &[3, b'w', b'w', b'w', 0xC0, 12],
    ))
    .unwrap();
    assert_eq!(message.answers[0].data, RData::Cname(name("www.a.example")));
}

#[test]
fn rejects_invalid_caa_tag() {
    let result = Message::decode(&answer_packet(RecordType::CAA, &[0, 0]));
    assert!(matches!(result, Err(Error::InvalidRdata { .. })));
    let result = Message::decode(&answer_packet(RecordType::CAA, b"\x00\x02a-x"));
    assert!(matches!(result, Err(Error::InvalidRdata { .. })));
}

#[test]
fn rejects_misplaced_or_duplicate_opt() {
    // OPT in the answer section.
    let result = Message::decode(&answer_packet(RecordType::OPT, &[]));
    assert!(matches!(result, Err(Error::InvalidOpt { .. })));

    let opt = [0, 0, 41, 4, 0xD0, 0, 0, 0, 0, 0, 0];
    // Two OPT records.
    let mut packet = header(0, [0, 0, 0, 2]);
    packet.extend_from_slice(&opt);
    packet.extend_from_slice(&opt);
    assert_eq!(
        Message::decode(&packet),
        Err(Error::InvalidOpt {
            reason: "more than one OPT record"
        })
    );
    // OPT with a non-root owner.
    let mut packet = header(0, [0, 0, 0, 1]);
    packet.extend_from_slice(&[1, b'a']);
    packet.extend_from_slice(&opt);
    assert!(matches!(
        Message::decode(&packet),
        Err(Error::InvalidOpt { .. })
    ));
    // OPT option running past the RDATA.
    let mut packet = header(0, [0, 0, 0, 1]);
    packet.extend_from_slice(&[0, 0, 41, 4, 0xD0, 0, 0, 0, 0, 0, 5, 0, 10, 0, 8, 1]);
    assert!(matches!(
        Message::decode(&packet),
        Err(Error::Truncated { .. })
    ));
}

#[test]
fn extended_rcode_combines_header_and_opt() {
    // Header RCODE 0, OPT extended RCODE 1: BADVERS (16).
    let mut packet = header(0x8000, [0, 0, 0, 1]);
    packet.extend_from_slice(&[0, 0, 41, 4, 0xD0, 1, 0, 0, 0, 0, 0]);
    let message = Message::decode(&packet).unwrap();
    assert_eq!(message.header.rcode, Rcode::BADVERS);
    assert_eq!(message.encode().unwrap(), packet);
}

// --- Known answers --------------------------------------------------------

/// An out-of-band interaction server's DNS response, built by hand byte by
/// byte, as the known answer.
fn hand_built_oob_response(query: &[u8], question_end: usize, answer: Ipv4Addr) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&query[0..2]);
    response.extend_from_slice(&[0x84, 0x00, 0, 1, 0, 1, 0, 0, 0, 0]);
    response.extend_from_slice(&query[12..question_end]);
    response.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 0x3C, 0, 4]);
    response.extend_from_slice(&answer.octets());
    response
}

#[test]
fn builds_the_hand_built_oob_response() {
    let query = Message::query(
        0x4242,
        Question::new(name("c0ffee.oob.example"), RecordType::A),
    )
    .with_recursion_desired(false);
    let query_bytes = query.encode().unwrap();
    let ip = Ipv4Addr::new(203, 0, 113, 7);

    let received = Message::decode(&query_bytes).unwrap();
    let question = &received.questions[0];
    assert_eq!(question.name.labels().next(), Some(&b"c0ffee"[..]));
    let response = Message::response_to(&received)
        .with_authoritative(true)
        .with_answer(Record::new(question.name.clone(), 60, RData::A(ip)));

    assert_eq!(
        response.encode().unwrap(),
        hand_built_oob_response(&query_bytes, query_bytes.len(), ip)
    );
}

#[test]
fn query_known_answer() {
    // RFC 1035-style query for example.com A, id 0x1234, RD set.
    let query = Message::query(0x1234, Question::new(name("example.com"), RecordType::A));
    assert_eq!(
        query.encode().unwrap(),
        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\
          \x07example\x03com\x00\x00\x01\x00\x01"
    );
    // With EDNS(0) and DO: an OPT record at the end, ARCOUNT 1.
    let query = query.with_edns(Edns::default().with_dnssec_ok(true));
    let bytes = query.encode().unwrap();
    assert_eq!(&bytes[10..12], &[0, 1]);
    assert_eq!(
        &bytes[bytes.len() - 11..],
        &[0, 0, 41, 0x04, 0xD0, 0, 0, 0x80, 0, 0, 0]
    );
}

#[test]
fn compresses_rfc1035_names_but_not_srv_or_rrsig() {
    let zone = name("example.com");
    let message = Message::default()
        .with_question(Question::new(zone.clone(), RecordType::ANY))
        .with_answer(Record::new(
            zone.clone(),
            1,
            RData::Ns(name("ns.example.com")),
        ))
        .with_answer(Record::new(
            zone.clone(),
            1,
            RData::Srv(Srv {
                priority: 0,
                weight: 0,
                port: 1,
                target: name("example.com"),
            }),
        ))
        .with_answer(Record::new(
            zone.clone(),
            1,
            RData::Rrsig(Rrsig {
                type_covered: RecordType::NS,
                algorithm: 13,
                labels: 2,
                original_ttl: 1,
                expiration: 2,
                inception: 1,
                key_tag: 3,
                signer_name: zone,
                signature: vec![1, 2, 3],
            }),
        ));
    let bytes = message.encode().unwrap();
    // NS RDATA: "ns" + pointer to the question name.
    assert!(bytes.windows(5).any(|w| w == b"\x02ns\xC0\x0C"));
    // SRV target and RRSIG signer: written out in full, twice.
    let full = b"\x07example\x03com\x00";
    let count = bytes.windows(full.len()).filter(|w| w == full).count();
    assert_eq!(count, 3, "question + SRV target + RRSIG signer");
    assert_eq!(Message::decode(&bytes).unwrap(), message);
}

#[test]
fn compression_preserves_case() {
    let message = Message::default()
        .with_question(Question::new(name("Example.COM"), RecordType::A))
        .with_answer(Record::new(
            name("example.com"),
            1,
            RData::A(Ipv4Addr::LOCALHOST),
        ));
    let decoded = Message::decode(&message.encode().unwrap()).unwrap();
    assert_eq!(decoded.answers[0].name.to_string(), "example.com");
    assert_eq!(decoded.questions[0].name.to_string(), "Example.COM");
}

// --- Builders and encoding errors ------------------------------------------

#[test]
fn response_to_copies_what_rfc_requires() {
    let mut query = Message::query(9, Question::new(name("a.example"), RecordType::TXT)).with_edns(
        Edns::default()
            .with_dnssec_ok(true)
            .with_udp_payload_size(4096)
            .with_option(EdnsOption::new(EdnsOption::COOKIE, vec![1; 8])),
    );
    query.header.checking_disabled = true;
    query.header.opcode = Opcode::QUERY;
    let response = Message::response_to(&query).with_rcode(Rcode::NXDOMAIN);
    assert_eq!(
        response.header,
        Header {
            id: 9,
            response: true,
            recursion_desired: true,
            checking_disabled: true,
            rcode: Rcode::NXDOMAIN,
            ..Header::default()
        }
    );
    assert_eq!(response.questions, query.questions);
    let edns = response.edns.clone().unwrap();
    assert!(edns.dnssec_ok());
    assert_eq!(edns.udp_payload_size, 1232);
    assert_eq!(edns.options, []);
    assert_eq!(
        Message::decode(&response.encode().unwrap()).unwrap(),
        response
    );
}

#[test]
fn encode_rejects_values_that_do_not_fit() {
    let base = Message::query(1, Question::new(name("a.example"), RecordType::A));

    let mut bad = base.clone();
    bad.header.opcode = Opcode(16);
    assert!(matches!(
        bad.encode(),
        Err(Error::OutOfRange {
            field: "opcode",
            ..
        })
    ));

    let bad = base.clone().with_rcode(Rcode::BADVERS);
    assert!(matches!(
        bad.encode(),
        Err(Error::OutOfRange { field: "rcode", .. })
    ));
    let ok = base
        .clone()
        .with_rcode(Rcode::BADVERS)
        .with_edns(Edns::default());
    assert!(ok.encode().is_ok());
    let bad = base
        .clone()
        .with_rcode(Rcode(4096))
        .with_edns(Edns::default());
    assert!(matches!(
        bad.encode(),
        Err(Error::OutOfRange { field: "rcode", .. })
    ));

    let bad = base.clone().with_answer(Record::new(
        name("a.example"),
        1,
        RData::Txt(vec![vec![0; 256]]),
    ));
    assert_eq!(
        bad.encode(),
        Err(Error::CharacterStringTooLong { len: 256 })
    );

    let bad = base.clone().with_answer(Record::new(
        name("a.example"),
        1,
        RData::Unknown {
            rtype: RecordType::OPT,
            data: vec![],
        },
    ));
    assert!(matches!(bad.encode(), Err(Error::InvalidOpt { .. })));

    let bad = base.with_answer(Record::new(
        name("a.example"),
        1,
        RData::Unknown {
            rtype: RecordType(65_280),
            data: vec![0; 65_536],
        },
    ));
    assert!(matches!(
        bad.encode(),
        Err(Error::RdataTooLong { .. } | Error::MessageTooLong { .. })
    ));
}

#[test]
fn encode_rejects_messages_over_64k() {
    let mut message = Message::query(1, Question::new(name("a.example"), RecordType::TXT));
    for _ in 0..300 {
        message.answers.push(Record::new(
            name("a.example"),
            1,
            RData::txt(vec![b'x'; 250]),
        ));
    }
    assert!(matches!(
        message.encode(),
        Err(Error::MessageTooLong { .. })
    ));
    // ...but it can still be truncated to fit.
    let bytes = message.encode_with_limit(usize::MAX).unwrap();
    assert!(bytes.len() <= 65_535);
    assert!(Message::decode(&bytes).unwrap().header.truncated);
}

#[test]
fn truncation_drops_whole_records_and_sets_tc() {
    let owner = name("host.example");
    let mut message = Message::response_to(
        &Message::query(5, Question::new(owner.clone(), RecordType::A)).with_edns(Edns::default()),
    );
    for i in 0..100_u8 {
        message.answers.push(Record::new(
            owner.clone(),
            60,
            RData::A(Ipv4Addr::new(10, 0, 0, i)),
        ));
    }
    message
        .additionals
        .push(Record::new(owner.clone(), 60, RData::txt("extra")));

    let bytes = message.encode_with_limit(512).unwrap();
    assert!(bytes.len() <= 512);
    let decoded = Message::decode(&bytes).unwrap();
    assert!(decoded.header.truncated);
    assert!(decoded.edns.is_some(), "OPT is kept");
    assert!(!decoded.answers.is_empty() && decoded.answers.len() < 100);
    assert_eq!(
        decoded.answers[..],
        message.answers[..decoded.answers.len()]
    );
    assert_eq!(decoded.additionals, []);

    // Dropping only additional records leaves TC clear.
    let mut small = message.clone();
    small.answers.truncate(2);
    small.additionals = vec![Record::new(owner, 60, RData::txt(vec![b'y'; 600]))];
    let decoded = Message::decode(&small.encode_with_limit(512).unwrap()).unwrap();
    assert!(!decoded.header.truncated);
    assert_eq!(decoded.answers.len(), 2);
    assert_eq!(decoded.additionals, []);

    // Everything fits: identical to encode().
    assert_eq!(
        small.encode_with_limit(65_535).unwrap(),
        small.encode().unwrap()
    );

    // Not even the question fits.
    assert!(matches!(
        message.encode_with_limit(20),
        Err(Error::MessageTooLong { .. })
    ));
}

#[test]
fn record_and_question_builders() {
    let record =
        Record::new(name("a.example"), 5, RData::A(Ipv4Addr::LOCALHOST)).with_class(Class::CH);
    assert_eq!(record.class, Class::CH);
    assert_eq!(record.rtype(), RecordType::A);
    assert_eq!(record.to_string(), "a.example 5 CH A 127.0.0.1");
    let question = Question::new(name("a.example"), RecordType::MX).with_class(Class::ANY);
    assert_eq!(question.to_string(), "a.example ANY MX");
}

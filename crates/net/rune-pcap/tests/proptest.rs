//! Property tests: what is written reads back the same, in both formats
//! and byte orders, and no input makes a reader panic.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail loudly on bad fixtures"
)]

use proptest::prelude::*;
use rune_pcap::pcapng::{Block, EnhancedPacketBuilder, InterfaceBuilder, SectionBuilder};
use rune_pcap::{
    CaptureReader, Endian, LinkType, PcapHeader, PcapNgReader, PcapNgWriter, PcapWriter, Precision,
    Timestamp, TsResolution,
};

#[derive(Debug, Clone)]
struct Pkt {
    secs: u32,
    nanos: u32,
    data: Vec<u8>,
    extra: u16,
    comment: Option<String>,
}

fn pkt() -> impl Strategy<Value = Pkt> {
    (
        any::<u32>(),
        0u32..1_000_000_000,
        proptest::collection::vec(any::<u8>(), 0..200),
        any::<u16>(),
        proptest::option::of("[a-z ]{0,20}"),
    )
        .prop_map(|(secs, nanos, data, extra, comment)| Pkt {
            secs,
            nanos,
            data,
            extra,
            comment,
        })
}

fn endian() -> impl Strategy<Value = Endian> {
    prop_oneof![Just(Endian::Little), Just(Endian::Big)]
}

fn resolution() -> impl Strategy<Value = TsResolution> {
    prop_oneof![
        (0u8..=9).prop_map(TsResolution::Decimal),
        (0u8..=30).prop_map(TsResolution::Binary),
    ]
}

/// The timestamp a resolution can hold: whole ticks, rounded down.
fn at(resolution: TsResolution, ts: Timestamp) -> Timestamp {
    resolution.to_timestamp(resolution.to_ticks(ts).unwrap())
}

proptest! {
    #[test]
    fn pcap_round_trip(
        endian in endian(),
        nanos in any::<bool>(),
        link in any::<u16>(),
        packets in proptest::collection::vec(pkt(), 0..8),
    ) {
        let precision = if nanos { Precision::Nanos } else { Precision::Micros };
        let header = PcapHeader::new(LinkType(link)).with_endian(endian).with_precision(precision);
        let mut w = PcapWriter::new(Vec::new(), header).unwrap();
        for p in &packets {
            let orig = u32::try_from(p.data.len()).unwrap() + u32::from(p.extra);
            w.write_truncated(Timestamp::new(p.secs.into(), p.nanos), &p.data, orig).unwrap();
        }
        let file = w.into_inner();
        let mut r = CaptureReader::new(file.as_slice()).unwrap();
        for p in &packets {
            let rec = r.next_packet().unwrap().unwrap();
            let ns = if nanos { p.nanos } else { p.nanos / 1_000 * 1_000 };
            prop_assert_eq!(rec.timestamp, Some(Timestamp::new(p.secs.into(), ns)));
            prop_assert_eq!(rec.data, &p.data[..]);
            prop_assert_eq!(rec.link_type, LinkType(link));
            prop_assert_eq!(rec.original_len as usize, p.data.len() + usize::from(p.extra));
        }
        prop_assert!(r.next_packet().unwrap().is_none());
    }

    #[test]
    fn pcapng_round_trip(
        sections in proptest::collection::vec(
            (
                endian(),
                proptest::collection::vec((any::<u16>(), resolution(), -1000i64..1000), 1..4),
                proptest::collection::vec((any::<prop::sample::Index>(), pkt()), 0..6),
            ),
            1..3,
        ),
    ) {
        let mut w: Option<PcapNgWriter<Vec<u8>>> = None;
        let mut expected = Vec::new();
        for (endian, interfaces, packets) in &sections {
            let shb = SectionBuilder::new().with_endian(*endian);
            match w.as_mut() {
                None => w = Some(PcapNgWriter::new(Vec::new(), &shb).unwrap()),
                Some(w) => w.new_section(&shb).unwrap(),
            }
            let w = w.as_mut().unwrap();
            for (link, res, offset) in interfaces {
                w.add_interface(
                    &InterfaceBuilder::new(LinkType(*link))
                        .with_ts_resolution(*res)
                        .with_ts_offset(*offset),
                )
                .unwrap();
            }
            for (index, p) in packets {
                let id = index.index(interfaces.len());
                let (link, res, offset) = interfaces[id];
                // Keep timestamps after the interface's offset.
                let ts = Timestamp::new(u64::from(p.secs) + 1000, p.nanos);
                let orig = u32::try_from(p.data.len()).unwrap() + u32::from(p.extra);
                let id = u32::try_from(id).unwrap();
                let mut epb = EnhancedPacketBuilder::new(id, ts, &p.data).with_original_len(orig);
                if let Some(c) = &p.comment {
                    epb = epb.with_comment(c);
                }
                w.write(&epb).unwrap();
                let shifted = ts.offset_secs(-offset);
                expected.push((id, LinkType(link), at(res, shifted).offset_secs(offset), p.clone(), orig));
            }
        }
        let file = w.unwrap().into_inner();

        let mut r = CaptureReader::new(file.as_slice()).unwrap();
        for (id, link, ts, p, orig) in &expected {
            let rec = r.next_packet().unwrap().unwrap();
            prop_assert_eq!(rec.interface_id, *id);
            prop_assert_eq!(rec.link_type, *link);
            prop_assert_eq!(rec.timestamp, Some(*ts));
            prop_assert_eq!(rec.data, &p.data[..]);
            prop_assert_eq!(rec.original_len, *orig);
        }
        prop_assert!(r.next_packet().unwrap().is_none());

        // Comments survive at the block level.
        let mut r = PcapNgReader::new(file.as_slice());
        let mut comments = Vec::new();
        while let Some(block) = r.next_block().unwrap() {
            if let Block::EnhancedPacket(epb) = block {
                comments.push(epb.options.comments().next().map(str::to_owned));
            }
        }
        let want: Vec<_> = expected.iter().map(|e| e.3.comment.clone()).collect();
        prop_assert_eq!(comments, want);
    }

    #[test]
    fn ticks_round_trip(res in resolution(), ticks in any::<u64>()) {
        let ts = res.to_timestamp(ticks);
        // Decimal up to nanoseconds: exact. Binary: rounding to whole
        // nanoseconds loses under 1 + 2^n / 10^9 ticks.
        let back = res.to_ticks(ts).unwrap();
        match res {
            TsResolution::Decimal(_) => prop_assert_eq!(back, ticks),
            TsResolution::Binary(n) => {
                prop_assert!(back <= ticks);
                prop_assert!(ticks - back <= 1 + (1u64 << n) / 1_000_000_000);
            }
            _ => {}
        }
    }

    #[test]
    fn readers_never_panic(data in proptest::collection::vec(any::<u8>(), 0..512)) {
        if let Ok(mut r) = CaptureReader::new(data.as_slice()) {
            for _ in 0..64 {
                match r.next_packet() {
                    Ok(Some(rec)) => {
                        let _ = rec.dissect();
                    }
                    _ => break,
                }
            }
        }
        let mut r = PcapNgReader::new(data.as_slice());
        for _ in 0..64 {
            if !matches!(r.next_block(), Ok(Some(_))) {
                break;
            }
        }
    }

    #[test]
    fn readers_never_panic_on_mutated_files(
        flips in proptest::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..8),
        cut in any::<prop::sample::Index>(),
    ) {
        let mut file = include_bytes!("fixtures/le-nanos.pcapng").to_vec();
        for (at, byte) in &flips {
            let i = at.index(file.len());
            file[i] = *byte;
        }
        file.truncate(cut.index(file.len() + 1));
        if let Ok(mut r) = CaptureReader::new(file.as_slice()) {
            while let Ok(Some(rec)) = r.next_packet() {
                let _ = rec.dissect();
            }
        }
    }
}

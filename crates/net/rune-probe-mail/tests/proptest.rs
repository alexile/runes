//! Reply parsing round trips, and no panics on arbitrary input.

use proptest::prelude::*;
use rune_probe_mail::{FtpProbe, SmtpProbe, parse_reply};
use rune_service_probe::{Options, Target, simulate};

/// Encode a reply the way SMTP servers do: `ddd-` on every line but the
/// last, which is `ddd `.
fn encode(code: u16, lines: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let sep = if i + 1 == lines.len() { ' ' } else { '-' };
        out.extend_from_slice(format!("{code}{sep}{line}\r\n").as_bytes());
    }
    out
}

proptest! {
    #[test]
    fn reply_round_trip(
        code in 100u16..600,
        lines in prop::collection::vec("[!-\\[\\]-~][ -\\[\\]-~]{0,40}", 1..20),
        split in any::<prop::sample::Index>(),
    ) {
        let bytes = encode(code, &lines);
        let (reply, used) = parse_reply(&bytes).unwrap().unwrap();
        prop_assert_eq!(reply.code, code);
        prop_assert_eq!(&reply.lines, &lines);
        prop_assert_eq!(used, bytes.len());
        // Any strict prefix is incomplete, never an error or a reply.
        let cut = split.index(bytes.len());
        prop_assert_eq!(parse_reply(&bytes[..cut]).unwrap(), None);
    }

    #[test]
    fn parser_never_panics(data in prop::collection::vec(any::<u8>(), 0..1024)) {
        if let Ok(Some((reply, used))) = parse_reply(&data) {
            prop_assert!(used <= data.len());
            for line in &reply.lines {
                prop_assert!(line.bytes().all(|b| (0x20..=0x7e).contains(&b)));
            }
        }
    }

    #[test]
    fn probes_never_panic(
        replies in prop::collection::vec(
            prop::collection::vec(any::<u8>(), 0..128).prop_map(|mut v| {
                v.splice(0..0, b"250-".iter().copied());
                v
            }),
            0..8,
        ),
        greeting in prop::sample::select(vec![&b"220 x\r\n"[..], b"220-a\r\n", b"120 wait\r\n"]),
        check in any::<bool>(),
    ) {
        let mut all: Vec<&[u8]> = vec![greeting];
        all.extend(replies.iter().map(Vec::as_slice));
        let target = Target::new("fuzz", 25);
        let smtp = SmtpProbe::new().with_starttls_check(check);
        let ftp = FtpProbe::new().with_auth_tls_check(check);
        for sim in [
            simulate(&smtp, &target, &all, &Options::default()).unwrap(),
            simulate(&ftp, &target, &all, &Options::default()).unwrap(),
        ] {
            prop_assert!(sim.sent.len() <= 4);
            if let Ok(info) = sim.result {
                let banner = info.banner.unwrap_or_default();
                prop_assert!(banner.bytes().all(|b| (0x20..=0x7e).contains(&b)));
            }
        }
    }
}

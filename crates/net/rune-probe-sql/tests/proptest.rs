//! The parsers and probe sessions never panic on arbitrary server bytes,
//! and the read-only probes send only their fixed requests.

use proptest::prelude::*;
use rune_probe_sql::{
    MssqlProbe, MysqlProbe, PostgresAuthProbe, PostgresProbe, mssql, mysql, postgres,
};
use rune_service_probe::{Options, ServiceProbe, Target, simulate};

fn replies() -> impl Strategy<Value = Vec<Vec<u8>>> {
    proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..96), 0..8)
}

proptest! {
    #[test]
    fn parsers_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = mysql::parse_greeting(&bytes);
        let _ = postgres::parse_message(&bytes);
        let _ = mssql::parse_response(&bytes);
    }

    #[test]
    fn mysql_greeting_round_trips_version(version in "[0-9][0-9a-zA-Z.+-]{0,40}", caps in any::<u32>()) {
        let mut p = vec![10];
        p.extend_from_slice(version.as_bytes());
        p.push(0);
        p.extend_from_slice(&[1, 0, 0, 0]);
        p.extend_from_slice(b"abcdefgh\0");
        p.extend_from_slice(&caps.to_le_bytes()[..2]);
        p.extend_from_slice(&[8, 2, 0]);
        p.extend_from_slice(&caps.to_le_bytes()[2..]);
        p.push(21);
        p.extend_from_slice(&[0; 10]);
        p.extend_from_slice(b"ijklmnopqrst\0mysql_native_password\0");
        let mut packet = vec![u8::try_from(p.len()).unwrap(), 0, 0, 0];
        packet.extend_from_slice(&p);
        let Ok(mysql::Greeting::Handshake(hs)) = mysql::parse_greeting(&packet) else {
            return Err(TestCaseError::fail("not parsed"));
        };
        prop_assert_eq!(hs.server_version, version);
        prop_assert_eq!(hs.capabilities, caps);
    }

    #[test]
    fn sessions_survive_arbitrary_replies(replies in replies(), max_read in 1usize..512) {
        let replies: Vec<&[u8]> = replies.iter().map(Vec::as_slice).collect();
        let options = Options::default().with_max_read_bytes(max_read).with_allow_intrusive(true);
        let target = Target::new("fuzz", 1);
        let probes: [&dyn ServiceProbe; 4] =
            [&MysqlProbe::new(), &PostgresProbe::new(), &MssqlProbe::new(), &PostgresAuthProbe::new()];
        for probe in probes {
            let sim = simulate(probe, &target, &replies, &options).unwrap();
            prop_assert!(sim.sent.len() <= 2);
            if let Ok(info) = sim.result {
                prop_assert_eq!(info.service, probe.id());
                for value in info.details.values() {
                    prop_assert!(value.len() <= 4 * 256);
                }
            }
        }
    }
}

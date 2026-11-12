//! Property tests: the EPSS CSV and dates round-trip, and no parser
//! panics.

use proptest::prelude::*;
use rune_cve::CveId;
use rune_epss::{Date, EpssScore, EpssSnapshot, KevCatalog};

proptest! {
    #[test]
    fn csv_round_trips(
        rows in proptest::collection::vec((1999u16..2100, 1u64..1_000_000, 0.0f64..=1.0, 0.0f64..=1.0), 0..40),
        model in proptest::option::of("v[0-9]{4}\\.[0-9]{2}\\.[0-9]{2}"),
        days in proptest::option::of(0i64..40_000),
    ) {
        let mut snapshot = EpssSnapshot::new();
        snapshot.model_version = model;
        snapshot.score_date = days.and_then(Date::from_unix_days);
        for (year, seq, epss, pct) in rows {
            snapshot.insert(CveId::new(year, seq).unwrap(), EpssScore::new(epss, pct).unwrap());
        }
        let csv = snapshot.to_csv();
        prop_assert_eq!(EpssSnapshot::from_csv(csv.as_bytes()).unwrap(), snapshot);
    }

    #[test]
    fn dates_round_trip(days in -719_528i64..=2_932_896) {
        let date = Date::from_unix_days(days).unwrap();
        prop_assert_eq!(date.to_unix_days(), days);
        prop_assert_eq!(date.to_string().parse::<Date>().unwrap(), date);
    }

    #[test]
    fn parsers_never_panic(s in "\\PC{0,80}") {
        let _ = EpssSnapshot::from_csv(s.as_bytes());
        let _ = EpssSnapshot::from_csv(format!("cve,epss,percentile\n{s}").as_bytes());
        let _ = EpssSnapshot::from_api_json(s.as_bytes());
        let _ = KevCatalog::from_json(s.as_bytes());
        let _ = s.parse::<Date>();
    }
}

//! Property tests: canonical round trips, order independence (v3), explicit
//! Not Defined values, score bounds, and no panics on arbitrary text.

use proptest::option;
use proptest::prelude::*;
use proptest::sample::select;
use rune_cvss::v3::{self, Minor};
use rune_cvss::v4;
use rune_cvss::{Score, Severity, Vector, Vector3, Vector4};

fn vector3() -> impl Strategy<Value = Vector3> {
    let base = (
        select(v3::AttackVector::ALL),
        select(v3::AttackComplexity::ALL),
        select(v3::PrivilegesRequired::ALL),
        select(v3::UserInteraction::ALL),
        select(v3::Scope::ALL),
        select(v3::Impact::ALL),
        select(v3::Impact::ALL),
        select(v3::Impact::ALL),
    )
        .prop_map(|(av, ac, pr, ui, s, c, i, a)| v3::Base {
            av,
            ac,
            pr,
            ui,
            s,
            c,
            i,
            a,
        });
    let temporal = (
        option::of(select(v3::ExploitCodeMaturity::ALL)),
        option::of(select(v3::RemediationLevel::ALL)),
        option::of(select(v3::ReportConfidence::ALL)),
    )
        .prop_map(|(e, rl, rc)| v3::Temporal { e, rl, rc });
    let environmental = (
        (
            option::of(select(v3::Requirement::ALL)),
            option::of(select(v3::Requirement::ALL)),
            option::of(select(v3::Requirement::ALL)),
        ),
        (
            option::of(select(v3::AttackVector::ALL)),
            option::of(select(v3::AttackComplexity::ALL)),
            option::of(select(v3::PrivilegesRequired::ALL)),
            option::of(select(v3::UserInteraction::ALL)),
            option::of(select(v3::Scope::ALL)),
            option::of(select(v3::Impact::ALL)),
            option::of(select(v3::Impact::ALL)),
            option::of(select(v3::Impact::ALL)),
        ),
    )
        .prop_map(
            |((cr, ir, ar), (mav, mac, mpr, mui, ms, mc, mi, ma))| v3::Environmental {
                cr,
                ir,
                ar,
                mav,
                mac,
                mpr,
                mui,
                ms,
                mc,
                mi,
                ma,
            },
        );
    (
        select(&[Minor::V3_0, Minor::V3_1][..]),
        base,
        temporal,
        environmental,
    )
        .prop_map(|(minor, base, temporal, environmental)| Vector3 {
            minor,
            base,
            temporal,
            environmental,
        })
}

fn vector4() -> impl Strategy<Value = Vector4> {
    let base = (
        (
            select(v4::AttackVector::ALL),
            select(v4::AttackComplexity::ALL),
            select(v4::AttackRequirements::ALL),
            select(v4::PrivilegesRequired::ALL),
            select(v4::UserInteraction::ALL),
        ),
        (
            select(v4::Impact::ALL),
            select(v4::Impact::ALL),
            select(v4::Impact::ALL),
            select(v4::Impact::ALL),
            select(v4::Impact::ALL),
            select(v4::Impact::ALL),
        ),
    )
        .prop_map(
            |((av, ac, at, pr, ui), (vc, vi, va, sc, si, sa))| v4::Base {
                av,
                ac,
                at,
                pr,
                ui,
                vc,
                vi,
                va,
                sc,
                si,
                sa,
            },
        );
    let threat = option::of(select(v4::ExploitMaturity::ALL)).prop_map(|e| v4::Threat { e });
    let environmental = (
        (
            option::of(select(v4::Requirement::ALL)),
            option::of(select(v4::Requirement::ALL)),
            option::of(select(v4::Requirement::ALL)),
            option::of(select(v4::AttackVector::ALL)),
            option::of(select(v4::AttackComplexity::ALL)),
            option::of(select(v4::AttackRequirements::ALL)),
            option::of(select(v4::PrivilegesRequired::ALL)),
        ),
        (
            option::of(select(v4::UserInteraction::ALL)),
            option::of(select(v4::Impact::ALL)),
            option::of(select(v4::Impact::ALL)),
            option::of(select(v4::Impact::ALL)),
            option::of(select(v4::Impact::ALL)),
            option::of(select(v4::ModifiedSubsequentImpact::ALL)),
            option::of(select(v4::ModifiedSubsequentImpact::ALL)),
        ),
    )
        .prop_map(
            |((cr, ir, ar, mav, mac, mat, mpr), (mui, mvc, mvi, mva, msc, msi, msa))| {
                v4::Environmental {
                    cr,
                    ir,
                    ar,
                    mav,
                    mac,
                    mat,
                    mpr,
                    mui,
                    mvc,
                    mvi,
                    mva,
                    msc,
                    msi,
                    msa,
                }
            },
        );
    let supplemental = (
        option::of(select(v4::Safety::ALL)),
        option::of(select(v4::Automatable::ALL)),
        option::of(select(v4::Recovery::ALL)),
        option::of(select(v4::ValueDensity::ALL)),
        option::of(select(v4::ResponseEffort::ALL)),
        option::of(select(v4::ProviderUrgency::ALL)),
    )
        .prop_map(|(s, au, r, v, re, u)| v4::Supplemental { s, au, r, v, re, u });
    (base, threat, environmental, supplemental).prop_map(
        |(base, threat, environmental, supplemental)| Vector4 {
            base,
            threat,
            environmental,
            supplemental,
        },
    )
}

fn in_bounds(score: Score) -> bool {
    (0.0..=10.0).contains(&score.value()) && score.tenths() <= 100
}

/// The `NAME:VALUE` parts of every v3 optional metric left Not Defined.
fn v3_undefined(vector: &Vector3) -> Vec<String> {
    let t = &vector.temporal;
    let e = &vector.environmental;
    [
        ("E", t.e.is_none()),
        ("RL", t.rl.is_none()),
        ("RC", t.rc.is_none()),
        ("CR", e.cr.is_none()),
        ("IR", e.ir.is_none()),
        ("AR", e.ar.is_none()),
        ("MAV", e.mav.is_none()),
        ("MAC", e.mac.is_none()),
        ("MPR", e.mpr.is_none()),
        ("MUI", e.mui.is_none()),
        ("MS", e.ms.is_none()),
        ("MC", e.mc.is_none()),
        ("MI", e.mi.is_none()),
        ("MA", e.ma.is_none()),
    ]
    .into_iter()
    .filter(|&(_, undefined)| undefined)
    .map(|(name, _)| format!("{name}:X"))
    .collect()
}

proptest! {
    #[test]
    fn v3_canonical_round_trip(vector in vector3()) {
        let text = vector.to_string();
        prop_assert_eq!(text.parse::<Vector3>(), Ok(vector));
        prop_assert_eq!(text.parse::<Vector>(), Ok(Vector::V3(vector)));
    }

    #[test]
    fn v3_any_order_and_explicit_x(
        vector in vector3(),
        order in any::<u64>(),
        with_x in any::<bool>(),
    ) {
        let text = vector.to_string();
        let (prefix, rest) = text.split_once('/').unwrap();
        let mut parts: Vec<String> = rest.split('/').map(str::to_owned).collect();
        if with_x {
            parts.extend(v3_undefined(&vector));
        }
        // A deterministic shuffle from the generated seed.
        let mut seed = order | 1;
        for i in (1..parts.len()).rev() {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let j = usize::try_from(seed % (i as u64 + 1)).unwrap();
            parts.swap(i, j);
        }
        let shuffled = format!("{prefix}/{}", parts.join("/"));
        prop_assert_eq!(shuffled.parse::<Vector3>(), Ok(vector));
    }

    #[test]
    fn v3_scores_in_bounds(vector in vector3()) {
        let base = vector.base_score();
        let temporal = vector.temporal_score();
        prop_assert!(in_bounds(base));
        prop_assert!(in_bounds(temporal));
        prop_assert!(in_bounds(vector.environmental_score()));
        // Temporal multipliers are at most 1.
        prop_assert!(temporal <= base);
        prop_assert_eq!(vector.severity(), Severity::from_score(vector.score()));
    }

    #[test]
    fn v4_canonical_round_trip(vector in vector4()) {
        let text = vector.to_string();
        prop_assert_eq!(text.parse::<Vector4>(), Ok(vector));
        prop_assert_eq!(text.parse::<Vector>(), Ok(Vector::V4(vector)));
    }

    #[test]
    fn v4_scores_in_bounds(vector in vector4()) {
        prop_assert!(in_bounds(vector.score()));
        prop_assert!(in_bounds(vector.base_score()));
        prop_assert!(in_bounds(vector.macro_vector().score()));
        prop_assert_eq!(vector.severity(), Severity::from_score(vector.score()));
        // Supplemental metrics never change the score.
        let mut plain = vector;
        plain.supplemental = v4::Supplemental::default();
        prop_assert_eq!(plain.score(), vector.score());
    }

    #[test]
    fn v4_out_of_order_is_rejected(vector in vector4(), index in any::<prop::sample::Index>()) {
        let text = vector.to_string();
        let parts: Vec<&str> = text.split('/').skip(1).collect();
        let i = index.index(parts.len() - 1);
        let mut swapped = parts.clone();
        swapped.swap(i, i + 1);
        let swapped = format!("CVSS:4.0/{}", swapped.join("/"));
        prop_assert!(swapped.parse::<Vector4>().is_err(), "{}", swapped);
    }

    #[test]
    fn arbitrary_text_never_panics(text in "\\PC{0,80}") {
        if let Ok(vector) = text.parse::<Vector>() {
            let canonical = vector.to_string();
            prop_assert_eq!(canonical.parse::<Vector>(), Ok(vector));
        }
    }

    #[test]
    fn near_valid_text_never_panics(
        vector in prop_oneof![vector3().prop_map(Vector::V3), vector4().prop_map(Vector::V4)],
        position in any::<prop::sample::Index>(),
        replacement in "[A-Za-z0-9:/.X]{0,3}",
    ) {
        let text = vector.to_string();
        let at = position.index(text.len());
        let mutated = format!("{}{replacement}{}", &text[..at], &text[(at + 1).min(text.len())..]);
        if let Ok(parsed) = mutated.parse::<Vector>() {
            prop_assert_eq!(parsed.to_string().parse::<Vector>(), Ok(parsed));
            prop_assert!(in_bounds(parsed.score()));
        }
    }
}

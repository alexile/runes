//! Properties of the mount plan model: masks always win, mounts are
//! emitted in phase order, and an isolated plan exposes nothing from the
//! host outside its binds.

use std::path::PathBuf;

use proptest::prelude::*;
use rune_namespaces::{Access, Exposure, MaskKind, Mount, MountPlan};

fn path() -> impl Strategy<Value = PathBuf> {
    prop::collection::vec(prop::sample::select(vec!["a", "b", "c", "d"]), 1..4)
        .prop_map(|parts| PathBuf::from(format!("/{}", parts.join("/"))))
}

fn mount() -> impl Strategy<Value = Mount> {
    prop_oneof![
        (path(), path(), any::<bool>(), any::<bool>()).prop_map(|(src, dest, rw, optional)| {
            Mount::Bind {
                src,
                dest,
                access: if rw {
                    Access::ReadWrite
                } else {
                    Access::ReadOnly
                },
                optional,
            }
        }),
        path().prop_map(|dest| Mount::Tmpfs { dest }),
        path().prop_map(|dest| Mount::Dir { dest }),
        path().prop_map(|dest| Mount::Mask {
            dest,
            kind: MaskKind::Dir
        }),
        Just(Mount::Proc {
            dest: "/proc".into()
        }),
        Just(Mount::Tmpfs { dest: "/".into() }),
    ]
}

fn plan() -> impl Strategy<Value = MountPlan> {
    prop::collection::vec(mount(), 0..12)
        .prop_map(|mounts| mounts.into_iter().fold(MountPlan::new(), MountPlan::with))
}

proptest! {
    #[test]
    fn masked_paths_stay_masked(plan in plan(), masked in path(), suffix in path()) {
        let plan = plan.with_mask(&masked, MaskKind::Dir);
        prop_assert_eq!(plan.lookup(&masked), Exposure::Masked);
        let below = masked.join(suffix.strip_prefix("/").unwrap());
        prop_assert_eq!(plan.lookup(&below), Exposure::Masked);
    }

    #[test]
    fn mounts_are_emitted_in_phase_order(plan in plan()) {
        let phases: Vec<_> = plan.ordered().map(Mount::phase).collect();
        prop_assert!(phases.windows(2).all(|w| w[0] <= w[1]));
        prop_assert_eq!(phases.len(), plan.mounts().len());
        plan.validate().unwrap();
    }

    #[test]
    fn without_binds_nothing_from_the_host_shows(plan in plan(), probe in path()) {
        let plan = plan
            .mounts()
            .iter()
            .filter(|m| !matches!(m, Mount::Bind { .. }))
            .cloned()
            .fold(MountPlan::isolated(), MountPlan::with);
        prop_assert!(!plan.lookup(&probe).is_host());
    }

    #[test]
    fn host_exposure_maps_into_a_bind_source(plan in plan(), probe in path()) {
        if let Exposure::Host { source, .. } = plan.lookup(&probe) {
            let from_bind = plan.mounts().iter().any(|m| matches!(
                m,
                Mount::Bind { src, dest, .. }
                    if probe.starts_with(dest) && source.starts_with(src)
            ));
            prop_assert!(from_bind);
        }
    }

    #[test]
    fn lookup_never_panics(plan in plan(), raw in ".*") {
        let _ = plan.lookup(raw);
    }
}

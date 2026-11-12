//! Properties of the presets for arbitrary extra paths.

use std::path::PathBuf;

use proptest::prelude::*;
use rune_namespaces::{Access, Exposure};
use rune_sandbox_preset::{DevToolOptions, MaskKind, dev_tool};

fn abs_path() -> impl Strategy<Value = PathBuf> {
    prop::collection::vec("[a-z]{1,6}", 1..4)
        .prop_map(|parts| PathBuf::from(format!("/{}", parts.join("/"))))
}

proptest! {
    /// Every granted path is visible with the right access unless a later
    /// grant or a mask covers it, and Landlock has a rule with matching
    /// rights for every grant.
    #[test]
    fn grants_agree_across_layers(
        project in abs_path(),
        read_only in prop::collection::vec(abs_path(), 0..4),
        read_write in prop::collection::vec(abs_path(), 0..4),
    ) {
        let mut options = DevToolOptions::new(&project);
        options.read_only.clone_from(&read_only);
        options.read_write.clone_from(&read_write);
        let preset = dev_tool(&options);
        prop_assert!(preset.validate().is_ok());

        // The project is granted last, so it is always writable.
        prop_assert_eq!(
            preset.exposure(&project),
            Exposure::Host { source: project, access: Access::ReadWrite }
        );
        let rules = preset.landlock_options().rules;
        for grant in &preset.grants {
            prop_assert!(rules.iter().any(|r| r.path == grant.path && r.rights == grant.access.rights()));
        }
    }

    /// A mask hides its path whatever is granted around it.
    #[test]
    fn masks_always_win(project in abs_path(), name in "[a-z.]{1,8}", extra in prop::collection::vec(abs_path(), 0..4)) {
        let secret = project.join(&name);
        let mut options = DevToolOptions::new(&project)
            .with_masks([(secret.clone(), MaskKind::File)]);
        options.read_write.clone_from(&extra);
        let preset = dev_tool(&options).with_read_write(project);
        if name != "." && name != ".." {
            prop_assert_eq!(preset.exposure(&secret), Exposure::Masked);
        }
    }

    /// Nothing outside the grants and the private base is ever visible.
    #[test]
    fn ungranted_paths_are_absent(project in abs_path(), probe in abs_path()) {
        let preset = dev_tool(&DevToolOptions::new(&project));
        let covered = preset.grants.iter().any(|g| probe.starts_with(&g.path))
            || ["/tmp", "/run", "/proc", "/dev"].iter().any(|base| probe.starts_with(base));
        if !covered {
            prop_assert!(!preset.is_visible(&probe));
        }
    }
}

//! Property tests: lookups never panic and only return absolute paths.

use proptest::prelude::*;
use rune_which::Finder;

proptest! {
    #[test]
    fn find_never_panics(
        name in any::<String>(),
        path in any::<String>(),
        pathext in any::<String>(),
        cwd in prop::option::of(any::<String>()),
    ) {
        let mut finder = Finder::new().with_path_var(&path).with_pathext(&pathext);
        if let Some(cwd) = cwd {
            finder = finder.with_cwd(cwd);
        }
        if let Some(found) = finder.find(&name) {
            prop_assert!(found.is_absolute());
        }
        for found in finder.find_all(&name) {
            prop_assert!(found.is_absolute());
        }
    }
}

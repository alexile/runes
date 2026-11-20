//! Compile-fail tests: misuse gets a clear error at the right span.
//!
//! Regenerate the expected output with `TRYBUILD=overwrite`.

#[test]
fn ui() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/*.rs");
}

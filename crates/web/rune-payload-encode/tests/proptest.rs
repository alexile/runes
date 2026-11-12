//! Property tests: reversible variants reverse, decoders never panic, and
//! the output stays within the configured bounds.

use proptest::prelude::*;
use rune_payload_encode::{Context, Encoder, Options, Technique};

#[cfg(test)]
fn encoder() -> Encoder {
    Encoder::new().unwrap_or_else(|e| panic!("{e}"))
}

fn technique() -> impl Strategy<Value = Technique> {
    proptest::sample::select(Technique::ALL.to_vec())
}

fn context() -> impl Strategy<Value = Context> {
    proptest::sample::select(Context::ALL.to_vec())
}

fn reversible() -> impl Strategy<Value = Technique> {
    let all: Vec<Technique> = Technique::ALL
        .into_iter()
        .filter(|t| t.is_reversible())
        .collect();
    proptest::sample::select(all)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Every technique accepts any text, and reversible ones reverse.
    #[test]
    fn single_techniques_reverse(payload in any::<String>(), technique in technique(), context in context()) {
        let encoder = encoder();
        let output = encoder.apply(technique, context, &payload);
        prop_assert!(output.is_ok(), "{technique}: {output:?}");
        let variants = encoder
            .evade(&payload, Context::Generic, &[technique])
            .unwrap_or_default();
        prop_assert_eq!(variants.len(), 1);
        if technique.is_reversible() {
            prop_assert_eq!(encoder.reverse(&variants[0]), Ok(payload.clone()));
            let sql = encoder.evade(&payload, Context::Sql, &[technique]).unwrap_or_default();
            if let Some(variant) = sql.first() {
                prop_assert_eq!(encoder.reverse(variant), Ok(payload));
            }
        }
    }

    /// Stacks of reversible techniques reverse as a whole.
    #[test]
    fn reversible_stacks_reverse(
        payload in "\\PC{0,24}",
        stack in proptest::collection::vec(reversible(), 1..4),
        context in context(),
    ) {
        let encoder = encoder();
        let options = Options::default()
            .with_context(context)
            .with_techniques([])
            .with_include_original(false)
            .with_stack(stack.clone());
        let report = encoder.run(&payload, &options);
        prop_assert!(report.is_ok());
        let report = report.unwrap_or_else(|e| panic!("{e}"));
        let applies = stack.iter().all(|t| t.applies_to(context));
        prop_assert_eq!(report.variants.len(), usize::from(applies));
        for variant in &report.variants {
            prop_assert_eq!(encoder.reverse(variant), Ok(payload.clone()));
        }
    }

    /// Decoding arbitrary input never panics.
    #[test]
    fn decoders_never_panic(input in any::<Vec<u8>>(), technique in technique(), context in context()) {
        let encoder = encoder();
        let transform = encoder.transform(technique, context);
        prop_assert!(transform.is_ok());
        if let Ok(transform) = transform {
            let _ = transform.decode(&input);
            let _ = transform.encode(&input);
        }
    }

    /// The limits hold for any payload and settings.
    #[test]
    fn output_is_bounded(
        payload in "\\PC{0,64}",
        context in context(),
        max_variants in 0usize..12,
        max_variant_len in 0usize..200,
    ) {
        let options = Options::default()
            .with_context(context)
            .with_techniques(Technique::ALL)
            .with_stack([Technique::DoubleUrlEncode, Technique::UnicodeEscape])
            .with_max_variants(max_variants)
            .with_max_variant_len(max_variant_len);
        let report = encoder().run(&payload, &options).unwrap_or_else(|e| panic!("{e}"));
        prop_assert!(report.variants.len() <= max_variants);
        for variant in report.variants.iter().filter(|v| !v.steps.is_empty()) {
            prop_assert!(variant.payload.len() <= max_variant_len);
        }
        // Deterministic: the same input gives the same report.
        prop_assert_eq!(encoder().run(&payload, &options).ok(), Some(report));
    }
}

#[test]
fn unicode_escape_uses_surrogate_pairs() {
    let encoder = encoder();
    let out = encoder
        .apply(Technique::UnicodeEscape, Context::Generic, "a\u{1f600}")
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(out, "\\u0061\\ud83d\\ude00");
}

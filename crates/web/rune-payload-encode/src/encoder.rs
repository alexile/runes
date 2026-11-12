//! Variant generation: [`Encoder`], [`Options`], [`Report`].

use std::collections::HashSet;
use std::sync::Arc;

use rune_transform::{Error as TransformError, Transform, TransformRegistry};

use crate::{Context, Error, Technique, register};

/// Label of the unmodified payload in a [`Report`].
pub const ORIGINAL: &str = "original";

/// One generated variant of a payload.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct Variant {
    /// Label: the technique name, the names of a stack joined with `+`
    /// (`case_toggle+url_encode`), or [`ORIGINAL`].
    pub technique: String,
    /// The techniques applied, in order; empty for the original.
    pub steps: Vec<Technique>,
    /// The context the variant was generated for.
    pub context: Context,
    /// The mutated payload.
    pub payload: String,
}

impl Variant {
    /// Whether [`Encoder::reverse`] recovers the original payload: every
    /// step is reversible.
    #[must_use]
    pub fn is_reversible(&self) -> bool {
        self.steps.iter().all(|step| step.is_reversible())
    }
}

/// Settings for [`Encoder::run`] and [`run`](crate::run).
///
/// The limits bound the work and the output: the payload length, the
/// length of every variant (including intermediate results of a stack),
/// and the number of variants.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Options {
    /// Injection context that scopes and tunes the techniques.
    pub context: Context,
    /// Techniques to apply one at a time, in output order. `None` means
    /// [`Context::default_techniques`].
    pub techniques: Option<Vec<Technique>>,
    /// Stacks of techniques applied in sequence, each yielding one variant
    /// after the single techniques.
    pub stacks: Vec<Vec<Technique>>,
    /// Emit the unmodified payload first, labelled [`ORIGINAL`].
    pub include_original: bool,
    /// Longest payload accepted, in bytes.
    pub max_payload_len: usize,
    /// Longest variant kept, in bytes. Longer ones are dropped and counted
    /// in [`Report::dropped`].
    pub max_variant_len: usize,
    /// Most variants returned, the original included.
    pub max_variants: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            context: Context::Generic,
            techniques: None,
            stacks: Vec::new(),
            include_original: true,
            max_payload_len: 64 * 1024,
            max_variant_len: 1024 * 1024,
            max_variants: 256,
        }
    }
}

impl Options {
    /// Set the injection context.
    #[must_use]
    pub const fn with_context(mut self, context: Context) -> Self {
        self.context = context;
        self
    }

    /// Apply exactly these techniques, in this order, instead of the
    /// context defaults.
    #[must_use]
    pub fn with_techniques(mut self, techniques: impl Into<Vec<Technique>>) -> Self {
        self.techniques = Some(techniques.into());
        self
    }

    /// Add a stack: the techniques are applied in sequence to produce one
    /// variant.
    #[must_use]
    pub fn with_stack(mut self, stack: impl Into<Vec<Technique>>) -> Self {
        self.stacks.push(stack.into());
        self
    }

    /// Whether to emit the original payload first.
    #[must_use]
    pub const fn with_include_original(mut self, include_original: bool) -> Self {
        self.include_original = include_original;
        self
    }

    /// Set the longest payload accepted.
    #[must_use]
    pub const fn with_max_payload_len(mut self, max: usize) -> Self {
        self.max_payload_len = max;
        self
    }

    /// Set the longest variant kept.
    #[must_use]
    pub const fn with_max_variant_len(mut self, max: usize) -> Self {
        self.max_variant_len = max;
        self
    }

    /// Set the most variants returned.
    #[must_use]
    pub const fn with_max_variants(mut self, max: usize) -> Self {
        self.max_variants = max;
        self
    }
}

/// The result of a run.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct Report {
    /// The context the variants were generated for.
    pub context: Context,
    /// The variants: the original (if asked for), then single techniques,
    /// then stacks, each in the order requested. Techniques that do not
    /// apply to the context are skipped, and a variant identical to an
    /// earlier non-original one is left out.
    pub variants: Vec<Variant>,
    /// Variants dropped for exceeding [`Options::max_variant_len`].
    pub dropped: usize,
    /// Whether generation stopped at [`Options::max_variants`].
    pub truncated: bool,
}

/// Generates evasion variants from a [`TransformRegistry`] holding the
/// evasion transforms.
///
/// Build it once and reuse it: [`new`](Self::new) builds the built-in
/// registry.
///
/// ```
/// use rune_payload_encode::{Context, Encoder, Options, Technique};
///
/// let encoder = Encoder::new()?;
/// let options = Options::default()
///     .with_context(Context::Sql)
///     .with_techniques([Technique::CaseToggle, Technique::SqlInlineComment])
///     .with_stack([Technique::SqlCharEncode, Technique::UrlEncode]);
/// let report = encoder.run("' OR 1=1-- -", &options)?;
/// let labels: Vec<_> = report.variants.iter().map(|v| v.technique.as_str()).collect();
/// assert_eq!(labels, ["original", "case_toggle", "sql_inline_comment", "sql_char_encode+url_encode"]);
/// assert_eq!(report.variants[2].payload, "'/**/OR/**/1=1--/**/-");
///
/// // Reversible variants decode back to the payload.
/// assert_eq!(encoder.reverse(&report.variants[3])?, "' OR 1=1-- -");
/// # Ok::<(), rune_payload_encode::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct Encoder {
    /// Built-ins plus the `evade_*` transforms.
    registry: TransformRegistry,
}

impl Encoder {
    /// An encoder over [`TransformRegistry::builtin`] plus the evasion
    /// transforms.
    ///
    /// # Errors
    /// Does not fail in practice; the error of [`register`] is passed on.
    pub fn new() -> Result<Self, Error> {
        Self::from_registry(TransformRegistry::builtin())
    }

    /// An encoder over `registry`, after [`register`]ing the evasion
    /// transforms in it.
    ///
    /// # Errors
    /// As for [`register`].
    pub fn from_registry(mut registry: TransformRegistry) -> Result<Self, Error> {
        register(&mut registry)?;
        Ok(Self { registry })
    }

    /// The registry, with the evasion transforms in it.
    #[must_use]
    pub const fn registry(&self) -> &TransformRegistry {
        &self.registry
    }

    /// Give back the registry, with the evasion transforms in it.
    #[must_use]
    pub fn into_registry(self) -> TransformRegistry {
        self.registry
    }

    /// The transform implementing `technique` in `context`.
    ///
    /// # Errors
    /// Returns [`Error::Transform`] if the transform was removed from the
    /// registry, which this type does not allow; kept for robustness.
    pub fn transform(
        &self,
        technique: Technique,
        context: Context,
    ) -> Result<Arc<dyn Transform>, Error> {
        let id = technique.transform_id(context);
        self.registry
            .get(id)
            .ok_or_else(|| TransformError::UnknownTransform { id: id.to_owned() }.into())
    }

    /// Apply one technique to `payload`, whether or not it
    /// [applies](Technique::applies_to) to `context`.
    ///
    /// # Errors
    /// Returns [`Error::Transform`] if the transform fails, which none does
    /// on UTF-8 input.
    pub fn apply(
        &self,
        technique: Technique,
        context: Context,
        payload: &str,
    ) -> Result<String, Error> {
        self.apply_steps(&[technique], context, payload.as_bytes(), usize::MAX)?
            .ok_or_else(|| unreachable_oversize(technique))
    }

    /// Apply each technique to `payload` on its own: techniques that do not
    /// apply to `context` are skipped and repeated outputs are left out. The
    /// original is not included, and the default [`Options`] limits apply.
    ///
    /// # Errors
    /// As for [`run`](Self::run).
    pub fn evade(
        &self,
        payload: &str,
        context: Context,
        techniques: &[Technique],
    ) -> Result<Vec<Variant>, Error> {
        let options = Options::default()
            .with_context(context)
            .with_techniques(techniques)
            .with_include_original(false);
        Ok(self.run(payload, &options)?.variants)
    }

    /// Generate the variants of `payload` described by `options`.
    ///
    /// Output order is deterministic: the original, the single techniques
    /// and then the stacks, each in the order given.
    ///
    /// # Errors
    /// Returns [`Error::PayloadTooLong`] when the payload exceeds
    /// [`Options::max_payload_len`], [`Error::EmptyStack`] for an empty
    /// stack, and [`Error::Transform`] if a transform fails.
    pub fn run(&self, payload: &str, options: &Options) -> Result<Report, Error> {
        if payload.len() > options.max_payload_len {
            return Err(Error::PayloadTooLong {
                len: payload.len(),
                max: options.max_payload_len,
            });
        }
        if options.stacks.iter().any(Vec::is_empty) {
            return Err(Error::EmptyStack);
        }
        let context = options.context;
        let mut report = Report {
            context,
            variants: Vec::new(),
            dropped: 0,
            truncated: false,
        };
        if options.include_original {
            if options.max_variants == 0 {
                report.truncated = true;
                return Ok(report);
            }
            // The original is not part of the de-duplication.
            report.variants.push(Variant {
                technique: ORIGINAL.to_owned(),
                steps: Vec::new(),
                context,
                payload: payload.to_owned(),
            });
        }

        let singles = options
            .techniques
            .as_deref()
            .unwrap_or_else(|| context.default_techniques());
        let jobs = singles
            .iter()
            .map(std::slice::from_ref)
            .chain(options.stacks.iter().map(Vec::as_slice));

        let mut seen = HashSet::new();
        for steps in jobs {
            if !steps.iter().all(|step| step.applies_to(context)) {
                continue;
            }
            let Some(output) =
                self.apply_steps(steps, context, payload.as_bytes(), options.max_variant_len)?
            else {
                report.dropped += 1;
                continue;
            };
            if seen.contains(&output) {
                continue;
            }
            if report.variants.len() >= options.max_variants {
                report.truncated = true;
                break;
            }
            seen.insert(output.clone());
            report.variants.push(Variant {
                technique: label(steps),
                steps: steps.to_vec(),
                context,
                payload: output,
            });
        }
        Ok(report)
    }

    /// Undo a variant, giving back the payload it was generated from.
    ///
    /// # Errors
    /// Returns [`Error::Transform`] with a not-reversible error naming the
    /// first one-way step when the variant [is not
    /// reversible](Variant::is_reversible), or a malformed-input error when
    /// `variant.payload` is not output of its steps.
    pub fn reverse(&self, variant: &Variant) -> Result<String, Error> {
        if let Some(step) = variant.steps.iter().find(|step| !step.is_reversible()) {
            return Err(TransformError::not_reversible(step.transform_id(variant.context)).into());
        }
        let mut current = variant.payload.as_bytes().to_vec();
        for &step in variant.steps.iter().rev() {
            current = self.transform(step, variant.context)?.decode(&current)?;
        }
        String::from_utf8(current).map_err(|_| TransformError::not_utf8("reverse").into())
    }

    /// Run `steps` in order; `None` when an intermediate or the final
    /// output exceeds `max_len`.
    fn apply_steps(
        &self,
        steps: &[Technique],
        context: Context,
        payload: &[u8],
        max_len: usize,
    ) -> Result<Option<String>, Error> {
        let mut current = payload.to_vec();
        for &step in steps {
            current = self.transform(step, context)?.encode(&current)?;
            if current.len() > max_len {
                return Ok(None);
            }
        }
        String::from_utf8(current)
            .map(Some)
            .map_err(|_| TransformError::not_utf8(label(steps).as_str()).into())
    }
}

/// The label of a variant built from `steps`.
fn label(steps: &[Technique]) -> String {
    let names: Vec<&str> = steps.iter().map(|step| step.name()).collect();
    names.join("+")
}

/// The error for an output over `usize::MAX` bytes, which cannot happen.
fn unreachable_oversize(technique: Technique) -> Error {
    TransformError::OutputTooLarge {
        transform: technique.name().to_owned(),
        limit: usize::MAX,
    }
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoder() -> Encoder {
        Encoder::new().unwrap_or_else(|e| panic!("{e}"))
    }

    fn labels(report: &Report) -> Vec<&str> {
        report
            .variants
            .iter()
            .map(|v| v.technique.as_str())
            .collect()
    }

    #[test]
    fn original_first_and_not_deduplicated() {
        let report = encoder()
            .run(
                "abc",
                &Options::default()
                    .with_context(Context::Sql)
                    .with_techniques([Technique::SqlInlineComment, Technique::SqlWhitespaceAlt]),
            )
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(labels(&report), ["original", "sql_inline_comment"]);
        assert_eq!(report.variants[1].payload, "abc");
    }

    #[test]
    fn limits_bound_the_output() {
        let encoder = encoder();
        assert_eq!(
            encoder.run("abcde", &Options::default().with_max_payload_len(4)),
            Err(Error::PayloadTooLong { len: 5, max: 4 })
        );

        let report = encoder
            .run("<a b>", &Options::default().with_max_variants(3))
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(report.variants.len(), 3);
        assert!(report.truncated);

        let none = encoder
            .run("x", &Options::default().with_max_variants(0))
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(none.variants.is_empty() && none.truncated);

        // `\uXXXX` is six bytes per character: over the limit, dropped.
        let report = encoder
            .run(
                "abcd",
                &Options::default()
                    .with_techniques([Technique::UnicodeEscape, Technique::CaseToggle])
                    .with_max_variant_len(8),
            )
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(labels(&report), ["original", "case_toggle"]);
        assert_eq!(report.dropped, 1);
        assert!(!report.truncated);
    }

    #[test]
    fn stacks_compose_and_respect_context() {
        let encoder = encoder();
        let options = Options::default()
            .with_context(Context::Xss)
            .with_techniques([])
            .with_include_original(false)
            .with_stack([Technique::CaseToggle, Technique::HtmlEntityEncode])
            .with_stack([Technique::SqlCharEncode, Technique::UrlEncode]);
        let report = encoder
            .run("<b>", &options)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(labels(&report), ["case_toggle+html_entity_encode"]);
        assert_eq!(report.variants[0].payload, "&lt;&#x42;&gt;");
        assert!(!report.variants[0].is_reversible());
        assert!(encoder.reverse(&report.variants[0]).is_err());

        assert_eq!(
            encoder.run("x", &Options::default().with_stack([])),
            Err(Error::EmptyStack)
        );
    }

    #[test]
    fn reverse_rejects_tampered_payloads() {
        let encoder = encoder();
        let mut variants = encoder
            .evade("1 OR 1", Context::Sql, &[Technique::SqlCharEncode])
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            encoder.reverse(&variants[0]).ok().as_deref(),
            Some("1 OR 1")
        );
        variants[0].payload.push('x');
        assert!(encoder.reverse(&variants[0]).is_err());
    }
}

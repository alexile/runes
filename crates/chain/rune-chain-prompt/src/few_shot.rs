use rune_chain_core::{ChainError, PromptArgs};

use crate::error::TemplateError;
use crate::template::{PromptTemplate, StringTemplate, legacy_error, push_unique};

/// A few-shot prompt: an optional prefix, a list of worked examples each
/// rendered through the same example template, and a suffix holding the
/// actual question.
///
/// The prefix and suffix see the caller's arguments; each example is
/// rendered only with its own arguments. Non-empty pieces are joined with a
/// separator (default: a blank line).
///
/// # Example
///
/// ```rust
/// use rune_chain_prompt::{FewShotTemplate, PromptTemplate, StringTemplate};
/// use rune_chain_core::prompt_args;
///
/// let tmpl = FewShotTemplate::try_new(
///     StringTemplate::new("Q: {q}\nA: {a}"),
///     vec![
///         prompt_args! { "q" => "2+2", "a" => "4" },
///         prompt_args! { "q" => "3*3", "a" => "9" },
///     ],
/// )?
/// .with_prefix(StringTemplate::new("Answer like the examples."))
/// .with_suffix(StringTemplate::new("Q: {question}\nA:"));
///
/// assert_eq!(tmpl.input_variables(), ["question"]);
/// let out = tmpl.format(&prompt_args! { "question" => "5-1" }).unwrap();
/// assert_eq!(out, "Answer like the examples.\n\nQ: 2+2\nA: 4\n\nQ: 3*3\nA: 9\n\nQ: 5-1\nA:");
/// # Ok::<(), rune_chain_prompt::TemplateError>(())
/// ```
#[derive(Debug, Clone)]
pub struct FewShotTemplate {
    example_template: StringTemplate,
    examples: Vec<PromptArgs>,
    prefix: Option<StringTemplate>,
    suffix: Option<StringTemplate>,
    separator: String,
}

impl FewShotTemplate {
    /// Create a few-shot template, checking that every example supplies
    /// every variable of `example_template`.
    ///
    /// Errors with [`TemplateError::InvalidExample`] naming the first bad
    /// example and its missing variables.
    pub fn try_new(
        example_template: StringTemplate,
        examples: Vec<PromptArgs>,
    ) -> Result<Self, TemplateError> {
        for (index, example) in examples.iter().enumerate() {
            let missing = example_template.missing_variables(example);
            if !missing.is_empty() {
                return Err(TemplateError::InvalidExample { index, missing });
            }
        }
        Ok(Self {
            example_template,
            examples,
            prefix: None,
            suffix: None,
            separator: "\n\n".to_owned(),
        })
    }

    /// Set the text placed before the examples.
    #[must_use]
    pub fn with_prefix(mut self, prefix: StringTemplate) -> Self {
        self.prefix = Some(prefix);
        self
    }

    /// Set the text placed after the examples (usually the real question).
    #[must_use]
    pub fn with_suffix(mut self, suffix: StringTemplate) -> Self {
        self.suffix = Some(suffix);
        self
    }

    /// Set the separator placed between pieces (default `"\n\n"`).
    #[must_use]
    pub fn with_separator(mut self, separator: impl Into<String>) -> Self {
        self.separator = separator.into();
        self
    }

    /// The examples, in order.
    #[must_use]
    pub fn examples(&self) -> &[PromptArgs] {
        &self.examples
    }

    /// Format the prompt, reporting every missing variable at once.
    pub fn try_format(&self, args: &PromptArgs) -> Result<String, TemplateError> {
        let missing = self.missing_variables(args);
        if !missing.is_empty() {
            return Err(TemplateError::MissingVariables(missing));
        }
        let mut pieces = Vec::with_capacity(self.examples.len() + 2);
        if let Some(prefix) = &self.prefix {
            pieces.push(prefix.try_format(args)?);
        }
        for example in &self.examples {
            pieces.push(self.example_template.try_format(example)?);
        }
        if let Some(suffix) = &self.suffix {
            pieces.push(suffix.try_format(args)?);
        }
        pieces.retain(|p| !p.is_empty());
        Ok(pieces.join(&self.separator))
    }

    fn missing_variables(&self, args: &PromptArgs) -> Vec<String> {
        let mut missing = Vec::new();
        for t in self.prefix.iter().chain(&self.suffix) {
            for v in t.missing_variables(args) {
                push_unique(&mut missing, &v);
            }
        }
        missing
    }
}

impl PromptTemplate for FewShotTemplate {
    fn format(&self, args: &PromptArgs) -> Result<String, ChainError> {
        self.try_format(args).map_err(legacy_error)
    }

    /// Variables of the prefix and suffix (examples bring their own).
    fn input_variables(&self) -> Vec<String> {
        let mut vars = Vec::new();
        for t in self.prefix.iter().chain(&self.suffix) {
            for v in t.input_variables() {
                push_unique(&mut vars, &v);
            }
        }
        vars
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rune_chain_core::prompt_args;

    #[test]
    fn rejects_incomplete_examples() {
        let err = FewShotTemplate::try_new(
            StringTemplate::new("{q} {a}"),
            vec![
                prompt_args! { "q" => 1, "a" => 2 },
                prompt_args! { "q" => 1 },
            ],
        )
        .unwrap_err();
        assert_eq!(
            err,
            TemplateError::InvalidExample {
                index: 1,
                missing: vec!["a".into()]
            }
        );
    }

    #[test]
    fn examples_only_with_custom_separator() {
        let t = FewShotTemplate::try_new(
            StringTemplate::new("{x}"),
            vec![prompt_args! { "x" => "a" }, prompt_args! { "x" => "b" }],
        )
        .unwrap()
        .with_separator("|");
        assert_eq!(t.input_variables().len(), 0);
        assert_eq!(t.format(&PromptArgs::new()).unwrap(), "a|b");
    }

    #[test]
    fn missing_suffix_variable() {
        let t = FewShotTemplate::try_new(StringTemplate::new("x"), vec![])
            .unwrap()
            .with_suffix(StringTemplate::new("{q}"));
        assert!(matches!(
            t.format(&PromptArgs::new()),
            Err(ChainError::MissingVariable(v)) if v == "q"
        ));
    }
}

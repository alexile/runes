//! [`Extractor`]: pull a typed value out of free text.

use std::fmt;
use std::marker::PhantomData;
use std::sync::Arc;

use rune_chain_core::{Llm, Message};
use rune_chain_output_parser::{self as parser, Mode, StructuredError, StructuredOutput};
use schemars::JsonSchema;
use serde::de::DeserializeOwned;

use crate::CompletionModel;
use crate::context::{DOCUMENTS_NOTICE, render_documents};

const DEFAULT_PREAMBLE: &str = "Extract the requested data from the user's text. \
Reply with a single JSON value that matches the schema. Use only facts stated in the text; \
leave optional fields out when the text does not give them.";

type Validator<T> = Box<dyn Fn(&T) -> Result<(), String> + Send + Sync>;

/// Builds an [`Extractor`]. Get one from
/// [`CompletionClient::extractor`](crate::CompletionClient::extractor), or
/// wrap any [`Llm`] with [`ExtractorBuilder::new`].
pub struct ExtractorBuilder<M, T> {
    model: M,
    preamble: Option<String>,
    context: Vec<String>,
    max_retries: Option<usize>,
    mode: Mode,
    strict: bool,
    validators: Vec<Validator<T>>,
    _marker: PhantomData<fn() -> T>,
}

impl<M, T> fmt::Debug for ExtractorBuilder<M, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExtractorBuilder")
            .field("type", &std::any::type_name::<T>())
            .field("mode", &self.mode)
            .field("max_retries", &self.max_retries)
            .finish_non_exhaustive()
    }
}

impl<M, T> ExtractorBuilder<M, T>
where
    M: Llm + 'static,
    T: JsonSchema + DeserializeOwned + Send + Sync + 'static,
{
    /// Start an extractor for `T` on `model`.
    pub fn new(model: M) -> Self {
        Self {
            model,
            preamble: None,
            context: Vec::new(),
            max_retries: None,
            mode: Mode::default(),
            strict: false,
            validators: Vec::new(),
            _marker: PhantomData,
        }
    }

    /// Replace the default extraction instructions.
    #[must_use]
    pub fn preamble(mut self, preamble: impl Into<String>) -> Self {
        self.preamble = Some(preamble.into());
        self
    }

    /// Add a reference document to the instructions (fenced as data).
    #[must_use]
    pub fn context(mut self, document: impl Into<String>) -> Self {
        self.context.push(document.into());
        self
    }

    /// How many times to re-ask the model, with the error, after an invalid
    /// answer (default 2).
    #[must_use]
    pub const fn max_retries(mut self, retries: usize) -> Self {
        self.max_retries = Some(retries);
        self
    }

    /// How to ask for JSON: the provider's structured output (default) or
    /// schema instructions in the prompt.
    #[must_use]
    pub const fn mode(mut self, mode: Mode) -> Self {
        self.mode = mode;
        self
    }

    /// Ask providers with strict structured output to enforce the schema
    /// exactly (`OpenAI` needs every property required and closed objects).
    #[must_use]
    pub const fn strict(mut self, strict: bool) -> Self {
        self.strict = strict;
        self
    }

    /// Add a business rule. A value it rejects is sent back to the model
    /// with the message, like a schema error.
    #[must_use]
    pub fn validator(
        mut self,
        validator: impl Fn(&T) -> Result<(), String> + Send + Sync + 'static,
    ) -> Self {
        self.validators.push(Box::new(validator));
        self
    }

    /// Build the extractor.
    ///
    /// # Errors
    ///
    /// [`StructuredError::InvalidSchema`] when the schema generated for `T`
    /// cannot be compiled.
    pub fn build(self) -> Result<Extractor<T>, StructuredError> {
        let mut inner = parser::Extractor::<T>::for_type()?
            .with_mode(self.mode)
            .with_strict(self.strict);
        if let Some(retries) = self.max_retries {
            inner = inner.with_max_retries(retries);
        }
        for validator in self.validators {
            inner = inner.with_validator(validator);
        }
        let mut system = self.preamble.unwrap_or_else(|| DEFAULT_PREAMBLE.to_owned());
        if let Some((docs, _)) =
            render_documents(self.context.iter().map(String::as_str), usize::MAX)
        {
            system = format!("{system}\n\n{docs}\n\n{DOCUMENTS_NOTICE}");
        }
        Ok(Extractor {
            llm: Arc::new(self.model),
            inner: Arc::new(inner),
            system,
        })
    }
}

impl<M: CompletionModel, T> ExtractorBuilder<M, T> {
    /// Sampling temperature of the model (0 suits extraction).
    #[must_use]
    pub fn temperature(mut self, temperature: f32) -> Self {
        self.model = self.model.with_temperature(temperature);
        self
    }

    /// Cap on tokens generated per model call.
    #[must_use]
    pub fn max_tokens(mut self, max_tokens: u32) -> Self {
        self.model = self.model.with_max_tokens(max_tokens);
        self
    }
}

/// Pulls a typed, schema-validated `T` out of free text, re-asking the
/// model with the error when its answer does not fit.
///
/// Built on `rune-chain-output-parser`: lenient JSON extraction, full JSON
/// Schema validation, size caps and the re-ask loop all come from there.
///
/// ```rust
/// use rune_chain::prelude::*;
/// use rune_chain::testing::FakeLlm;
/// use schemars::JsonSchema;
/// use serde::Deserialize;
///
/// #[derive(Debug, Deserialize, JsonSchema)]
/// struct Person { name: String, age: u32 }
///
/// # tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(async {
/// let llm = FakeLlm::with_replies([r#"{"name": "Ada", "age": 36}"#]);
/// let extractor = ExtractorBuilder::<_, Person>::new(llm).build().unwrap();
/// let person = extractor.extract("Ada Lovelace is 36.").await.unwrap();
/// assert_eq!(person.age, 36);
/// # });
/// ```
pub struct Extractor<T> {
    llm: Arc<dyn Llm>,
    inner: Arc<parser::Extractor<T>>,
    system: String,
}

impl<T> Clone for Extractor<T> {
    fn clone(&self) -> Self {
        Self {
            llm: Arc::clone(&self.llm),
            inner: Arc::clone(&self.inner),
            system: self.system.clone(),
        }
    }
}

impl<T> fmt::Debug for Extractor<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Extractor")
            .field("type", &std::any::type_name::<T>())
            .field("schema", &self.inner.name())
            .finish_non_exhaustive()
    }
}

impl<T: DeserializeOwned> Extractor<T> {
    /// Extract a `T` from `text`.
    ///
    /// # Errors
    ///
    /// Model failures, and [`StructuredError::RetriesExhausted`] when no
    /// answer fit the schema and validators.
    pub async fn extract(&self, text: impl AsRef<str> + Send) -> Result<T, StructuredError> {
        Ok(self.extract_with_details(text).await?.value)
    }

    /// [`extract`](Self::extract), also returning the raw answer, the
    /// validated JSON, the number of attempts and the token usage.
    ///
    /// # Errors
    ///
    /// As for [`extract`](Self::extract).
    pub async fn extract_with_details(
        &self,
        text: impl AsRef<str> + Send,
    ) -> Result<StructuredOutput<T>, StructuredError> {
        let messages = [
            Message::system(self.system.clone()),
            Message::human(text.as_ref()),
        ];
        self.inner.extract(self.llm.as_ref(), &messages).await
    }

    /// Extract a `T` from a whole conversation (the extraction instructions
    /// are put in front).
    ///
    /// # Errors
    ///
    /// As for [`extract`](Self::extract).
    pub async fn extract_from_messages(
        &self,
        messages: &[Message],
    ) -> Result<StructuredOutput<T>, StructuredError> {
        let mut all = Vec::with_capacity(messages.len() + 1);
        all.push(Message::system(self.system.clone()));
        all.extend_from_slice(messages);
        self.inner.extract(self.llm.as_ref(), &all).await
    }

    /// The JSON Schema the model is asked to fill.
    #[must_use]
    pub fn schema(&self) -> serde_json::Value {
        self.inner.parser().schema().as_value().clone()
    }
}

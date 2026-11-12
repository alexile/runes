use std::pin::Pin;

use async_trait::async_trait;
use futures::Stream;
use rune_chain_core::{Chain, ChainError, GenerateResult, PromptArgs, StreamData};

use crate::OutputParser;

/// Wraps a [`Chain`] and an [`OutputParser`] to produce typed output.
///
/// `ParsedChain<C, P, T>` runs the inner chain, takes the generated text, and
/// feeds it through the parser. The final output is serialized back into a
/// `GenerateResult` whose `generation` field contains the parsed value's `Debug`
/// representation, while `tokens` are forwarded unchanged.
///
/// For structured types, use [`ParsedChain::parse`] directly to get `T`.
///
/// # Example
///
/// ```rust,no_run
/// use rune_chain_output_parser::{ParsedChain, JsonOutputParser};
/// use rune_chain_core::{Chain, prompt_args};
/// use serde::Deserialize;
///
/// #[derive(Deserialize, Debug)]
/// struct Sentiment { label: String, score: f32 }
///
/// # async fn run() -> Result<(), rune_chain_core::ChainError> {
/// # use rune_chain_core::{GenerateResult, ChainError, PromptArgs};
/// # use async_trait::async_trait;
/// # struct FakeChain;
/// # #[async_trait] impl Chain for FakeChain {
/// #     async fn call(&self, _: PromptArgs) -> Result<GenerateResult, ChainError> {
/// #         Ok(GenerateResult::from_text(r#"{"label":"positive","score":0.95}"#))
/// #     }
/// # }
/// let chain = ParsedChain::new(FakeChain, JsonOutputParser::<Sentiment>::new());
/// let sentiment = chain.parse(prompt_args! { "text" => "I love this!" }).await?;
/// println!("{:?}", sentiment);
/// # Ok(())
/// # }
/// ```
pub struct ParsedChain<C, P, T>
where
    C: Chain,
    P: OutputParser<T>,
    T: std::fmt::Debug + Send + Sync + 'static,
{
    chain: C,
    parser: P,
    _phantom: std::marker::PhantomData<T>,
}

impl<C, P, T> ParsedChain<C, P, T>
where
    C: Chain,
    P: OutputParser<T>,
    T: std::fmt::Debug + Send + Sync + 'static,
{
    /// Create a `ParsedChain` wrapping `chain` with `parser`.
    pub const fn new(chain: C, parser: P) -> Self {
        Self {
            chain,
            parser,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Run the chain and parse the output, returning the typed `T`.
    pub async fn parse(&self, input: PromptArgs) -> Result<T, ChainError> {
        let result = self.chain.call(input).await?;
        self.parser.parse(&result.generation)
    }

    /// Return the optional format-instructions string from the parser.
    pub fn format_instructions(&self) -> Option<String> {
        self.parser.format_instructions()
    }
}

#[async_trait]
impl<C, P, T> Chain for ParsedChain<C, P, T>
where
    C: Chain,
    P: OutputParser<T>,
    T: std::fmt::Debug + Send + Sync + 'static,
{
    async fn call(&self, input: PromptArgs) -> Result<GenerateResult, ChainError> {
        let result = self.chain.call(input).await?;
        let parsed = self.parser.parse(&result.generation)?;
        Ok(GenerateResult::from_text(format!("{parsed:?}")).with_tokens(result.tokens))
    }

    async fn stream(
        &self,
        input: PromptArgs,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<StreamData, ChainError>> + Send>>, ChainError>
    {
        self.chain.stream(input).await
    }

    fn input_keys(&self) -> Vec<String> {
        self.chain.input_keys()
    }

    fn output_keys(&self) -> Vec<String> {
        self.chain.output_keys()
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use rune_chain_core::{ChainError, GenerateResult, PromptArgs, prompt_args};

    use super::*;
    use crate::JsonOutputParser;
    use serde::Deserialize;

    #[derive(Deserialize, Debug, PartialEq)]
    struct Point {
        x: i32,
        y: i32,
    }

    struct FixedChain(String);

    #[async_trait]
    impl Chain for FixedChain {
        async fn call(&self, _: PromptArgs) -> Result<GenerateResult, ChainError> {
            Ok(GenerateResult::from_text(&self.0))
        }
    }

    #[tokio::test]
    async fn parse_returns_typed_value() {
        let chain = ParsedChain::new(
            FixedChain(r#"{"x":1,"y":2}"#.into()),
            JsonOutputParser::<Point>::new(),
        );
        let point = chain.parse(prompt_args! {}).await.unwrap();
        assert_eq!(point, Point { x: 1, y: 2 });
    }

    #[tokio::test]
    async fn chain_call_returns_debug_string() {
        let chain = ParsedChain::new(
            FixedChain(r#"{"x":3,"y":4}"#.into()),
            JsonOutputParser::<Point>::new(),
        );
        let result = chain.call(prompt_args! {}).await.unwrap();
        assert!(result.generation.contains("Point"));
    }
}

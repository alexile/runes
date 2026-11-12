use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use rune_chain_core::{Chain, ChainError, GenerateResult, LlmError, PromptArgs};
use serde_json::Value;

use crate::RetryPolicy;

pub const RESULT_KEY: &str = "generate_result";

type ExitPredicate = Arc<dyn Fn(&GenerateResult) -> bool + Send + Sync>;

/// One step of a [`SequentialChain`](crate::SequentialChain): a chain, the
/// key its answer is stored under, and how it is run.
///
/// # Key mapping
///
/// A step sees every variable produced so far (the pipeline input plus the
/// outputs of earlier steps). [`map_input`](Self::map_input) additionally
/// exposes a pipeline variable under the name the step's chain expects, and
/// [`map_output`](Self::map_output) copies extra keys from the step's
/// [`Chain::execute`] map into the pipeline. Both are checked when the
/// pipeline is built.
///
/// # Example
///
/// ```rust
/// use std::time::Duration;
/// use rune_chain_core::{Chain, ChainError, GenerateResult, PromptArgs};
/// use rune_chain_sequential::{RetryPolicy, Step};
/// # use async_trait::async_trait;
/// # struct Summarize;
/// # #[async_trait]
/// # impl Chain for Summarize {
/// #     async fn call(&self, _: PromptArgs) -> Result<GenerateResult, ChainError> {
/// #         Ok(GenerateResult::from_text("short"))
/// #     }
/// #     fn input_keys(&self) -> Vec<String> { vec!["text".into()] }
/// # }
///
/// let step = Step::new(Summarize, "summary")
///     .name("summarize")
///     .map_input("text", "article")          // the chain reads `text`, fed from `article`
///     .timeout(Duration::from_secs(30))
///     .retry(RetryPolicy::new(3))
///     .exit_if(|r| r.generation.is_empty()); // nothing to summarize: stop here
/// assert_eq!(step.output_key(), "summary");
/// ```
pub struct Step {
    pub(crate) chain: Arc<dyn Chain>,
    pub(crate) output_key: String,
    pub(crate) name: Option<String>,
    pub(crate) inputs: Vec<(String, String)>,
    pub(crate) outputs: Vec<(String, String)>,
    pub(crate) timeout: Option<Duration>,
    pub(crate) retry: Option<RetryPolicy>,
    pub(crate) exit_if: Option<ExitPredicate>,
}

impl Step {
    /// Run `chain` and store its answer under `output_key`.
    #[must_use]
    pub fn new(chain: impl Chain + 'static, output_key: impl Into<String>) -> Self {
        Self::from_arc(Arc::new(chain), output_key)
    }

    /// Like [`new`](Self::new), for a chain that is shared elsewhere.
    #[must_use]
    pub fn from_arc(chain: Arc<dyn Chain>, output_key: impl Into<String>) -> Self {
        Self {
            chain,
            output_key: output_key.into(),
            name: None,
            inputs: Vec::new(),
            outputs: Vec::new(),
            timeout: None,
            retry: None,
            exit_if: None,
        }
    }

    /// A name for events, reports and errors (default: the output key).
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Give the step's chain the pipeline variable `from` under the name
    /// `as_key`.
    #[must_use]
    pub fn map_input(mut self, as_key: impl Into<String>, from: impl Into<String>) -> Self {
        self.inputs.push((as_key.into(), from.into()));
        self
    }

    /// Copy `key` from the step's [`Chain::execute`] map into the pipeline
    /// as `to`. The key must be one of the chain's
    /// [`output_keys`](Chain::output_keys). A step with output mappings is
    /// run through `execute` instead of `call`.
    #[must_use]
    pub fn map_output(mut self, key: impl Into<String>, to: impl Into<String>) -> Self {
        self.outputs.push((key.into(), to.into()));
        self
    }

    /// Fail the attempt with a [timeout error](LlmError::timeout) when it
    /// takes longer than `limit`. The limit applies to each attempt; a
    /// timed-out attempt counts as transient for [`RetryPolicy`].
    #[must_use]
    pub const fn timeout(mut self, limit: Duration) -> Self {
        self.timeout = Some(limit);
        self
    }

    /// Retry the step according to `policy`.
    #[must_use]
    pub fn retry(mut self, policy: RetryPolicy) -> Self {
        self.retry = Some(policy);
        self
    }

    /// Stop the pipeline after this step when `predicate` returns `true`
    /// for its result. The step's answer then becomes the pipeline's answer
    /// and the remaining steps do not run.
    #[must_use]
    pub fn exit_if(
        mut self,
        predicate: impl Fn(&GenerateResult) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.exit_if = Some(Arc::new(predicate));
        self
    }

    /// The key the step's answer is stored under.
    #[must_use]
    pub fn output_key(&self) -> &str {
        &self.output_key
    }

    /// The pipeline variables the step's chain gets, with input mappings
    /// applied.
    pub(crate) fn input_for(&self, vars: &PromptArgs) -> PromptArgs {
        let mut input = vars.clone();
        for (as_key, from) in &self.inputs {
            if let Some(value) = vars.get(from) {
                input.insert(as_key.clone(), value.clone());
            }
        }
        input
    }

    pub(crate) fn exits_on(&self, result: &GenerateResult) -> bool {
        self.exit_if.as_ref().is_some_and(|f| f(result))
    }

    /// One attempt, under the step's timeout.
    pub(crate) async fn run_once(
        &self,
        name: &str,
        input: PromptArgs,
    ) -> Result<(GenerateResult, Option<HashMap<String, Value>>), ChainError> {
        let attempt = async {
            if self.outputs.is_empty() {
                return self.chain.call(input).await.map(|r| (r, None));
            }
            let map = self.chain.execute(input).await?;
            let result = map
                .get(RESULT_KEY)
                .and_then(|v| serde_json::from_value::<GenerateResult>(v.clone()).ok())
                .unwrap_or_else(|| {
                    let text = map
                        .get(&self.chain.primary_output_key())
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    GenerateResult::from_text(text)
                });
            Ok((result, Some(map)))
        };
        match self.timeout {
            None => attempt.await,
            Some(limit) => tokio::time::timeout(limit, attempt)
                .await
                .unwrap_or_else(|_| Err(timeout_error(name, limit))),
        }
    }
}

pub fn timeout_error(name: &str, limit: Duration) -> ChainError {
    LlmError::timeout(format!("step `{name}` took longer than {limit:?}")).into()
}

impl fmt::Debug for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Step")
            .field("output_key", &self.output_key)
            .field("name", &self.name)
            .field("inputs", &self.inputs)
            .field("outputs", &self.outputs)
            .field("timeout", &self.timeout)
            .field("retry", &self.retry)
            .field("exit_if", &self.exit_if.is_some())
            .finish_non_exhaustive()
    }
}

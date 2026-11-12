use std::collections::{HashMap, HashSet};
use std::fmt;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures::{Stream, stream};
use rune_chain_core::{Chain, ChainError, GenerateResult, PromptArgs, StreamData, TokenUsage};
use serde_json::Value;
use tokio::time::Instant;

use crate::step::{RESULT_KEY, timeout_error};
use crate::{SequentialRun, Step, StepEvent, StepReport};

type EventHook = Arc<dyn Fn(&StepEvent<'_>) + Send + Sync>;
type ChainStream = Pin<Box<dyn Stream<Item = Result<StreamData, ChainError>> + Send>>;

/// A pipeline that cannot run, found by
/// [`SequentialChainBuilder::build`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BuildError {
    /// A step has an empty output key.
    #[error("step {index} has an empty output key")]
    EmptyOutputKey {
        /// Position of the step, from 0.
        index: usize,
    },
    /// A step writes `"generate_result"`, which the pipeline reserves.
    #[error("step `{step}` writes the reserved key `{key}`")]
    ReservedKey {
        /// The step's name.
        step: String,
        /// The reserved key.
        key: String,
    },
    /// A step writes a key that a pipeline input or an earlier step
    /// already provides.
    #[error("step `{step}` writes `{key}`, which is already a pipeline input or step output")]
    DuplicateKey {
        /// The step's name.
        step: String,
        /// The duplicated key.
        key: String,
    },
    /// A step needs a variable that neither the declared inputs nor any
    /// earlier step provides.
    #[error("step `{step}` needs `{key}`, which no declared input or earlier step provides")]
    MissingInput {
        /// The step's name.
        step: String,
        /// The missing variable.
        key: String,
    },
    /// An output mapping names a key the step's chain does not list in its
    /// output keys.
    #[error("step `{step}` maps output `{key}`, which its chain does not produce")]
    UnknownOutput {
        /// The step's name.
        step: String,
        /// The unknown key.
        key: String,
    },
}

impl From<BuildError> for ChainError {
    fn from(e: BuildError) -> Self {
        Self::Other(e.to_string())
    }
}

/// Builds a [`SequentialChain`], checking the key wiring up front.
///
/// Create one with [`SequentialChain::builder`].
#[must_use]
pub struct SequentialChainBuilder {
    steps: Vec<Step>,
    inputs: Option<Vec<String>>,
    step_timeout: Option<Duration>,
    on_event: Option<EventHook>,
}

impl fmt::Debug for SequentialChainBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SequentialChainBuilder")
            .field("steps", &self.steps)
            .field("inputs", &self.inputs)
            .field("step_timeout", &self.step_timeout)
            .finish_non_exhaustive()
    }
}

impl SequentialChainBuilder {
    /// Declare the pipeline's input variables.
    ///
    /// With inputs declared, [`build`](Self::build) rejects any step that
    /// needs a variable not in this list and not produced by an earlier
    /// step. Without them, every variable no earlier step produces is taken
    /// to be a pipeline input, and only its presence at run time is checked.
    pub fn inputs<I, S>(mut self, keys: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.inputs = Some(keys.into_iter().map(Into::into).collect());
        self
    }

    /// Append a configured [`Step`].
    pub fn step(mut self, step: Step) -> Self {
        self.steps.push(step);
        self
    }

    /// Append a step that runs `chain` and stores its answer under
    /// `output_key`; shorthand for `.step(Step::new(chain, output_key))`.
    pub fn chain(self, chain: impl Chain + 'static, output_key: impl Into<String>) -> Self {
        self.step(Step::new(chain, output_key))
    }

    /// Default per-attempt timeout for steps that do not set their own.
    pub const fn step_timeout(mut self, limit: Duration) -> Self {
        self.step_timeout = Some(limit);
        self
    }

    /// Call `hook` with a [`StepEvent`] as each step starts, retries,
    /// finishes, fails or exits. The hook runs inline, so keep it quick.
    pub fn on_event(mut self, hook: impl Fn(&StepEvent<'_>) + Send + Sync + 'static) -> Self {
        self.on_event = Some(Arc::new(hook));
        self
    }

    /// Check the key wiring and build the pipeline.
    ///
    /// A step "needs" each of its chain's
    /// [`input_keys`](Chain::input_keys) (after
    /// [`map_input`](Step::map_input) renaming) and each mapped input
    /// source. Chains that report no input keys are not checked.
    ///
    /// # Errors
    ///
    /// A [`BuildError`] for an empty, reserved or duplicated output key, a
    /// needed variable nothing provides (with declared inputs), or an output
    /// mapping the chain does not produce.
    pub fn build(mut self) -> Result<SequentialChain, BuildError> {
        let declared = self.inputs.is_some();
        let mut available: HashSet<String> = self.inputs.iter().flatten().cloned().collect();
        let mut inputs: Vec<String> = self.inputs.clone().unwrap_or_default();
        let mut names = Vec::with_capacity(self.steps.len());

        for (index, step) in self.steps.iter_mut().enumerate() {
            if step.output_key.is_empty() {
                return Err(BuildError::EmptyOutputKey { index });
            }
            let name = step.name.clone().unwrap_or_else(|| step.output_key.clone());

            let mut needs: Vec<String> = step.inputs.iter().map(|(_, from)| from.clone()).collect();
            for key in step.chain.input_keys() {
                let source = step
                    .inputs
                    .iter()
                    .find(|(as_key, _)| *as_key == key)
                    .map_or(key, |(_, from)| from.clone());
                needs.push(source);
            }
            for key in needs {
                if available.contains(&key) {
                    continue;
                }
                if declared {
                    return Err(BuildError::MissingInput { step: name, key });
                }
                available.insert(key.clone());
                inputs.push(key);
            }

            let produced = step.chain.output_keys();
            let mut writes = Vec::with_capacity(step.outputs.len() + 1);
            for (key, to) in &step.outputs {
                if !produced.contains(key) {
                    return Err(BuildError::UnknownOutput {
                        step: name,
                        key: key.clone(),
                    });
                }
                writes.push(to.clone());
            }
            writes.push(step.output_key.clone());
            for key in writes {
                if key == RESULT_KEY {
                    return Err(BuildError::ReservedKey { step: name, key });
                }
                if !available.insert(key.clone()) {
                    return Err(BuildError::DuplicateKey { step: name, key });
                }
            }

            if step.timeout.is_none() {
                step.timeout = self.step_timeout;
            }
            names.push(name);
        }

        Ok(SequentialChain {
            steps: self.steps,
            names,
            inputs,
            on_event: self.on_event,
        })
    }
}

/// An ordered pipeline of chains: each step's answer is stored under its
/// output key and is visible to every later step.
///
/// Build one with [`SequentialChain::builder`]. Running it returns the last
/// step's result with token usage summed across all steps; [`run`](Self::run)
/// also returns every step's output and a report per step.
///
/// # Example
///
/// ```rust
/// use std::sync::{Arc, Mutex};
///
/// use async_trait::async_trait;
/// use rune_chain_core::{Chain, ChainError, GenerateResult, PromptArgs, TokenUsage, prompt_args};
/// use rune_chain_sequential::{SequentialChain, Step, StepEvent};
///
/// /// Upper-cases the variable `from`.
/// struct Upper(&'static str);
///
/// #[async_trait]
/// impl Chain for Upper {
///     async fn call(&self, input: PromptArgs) -> Result<GenerateResult, ChainError> {
///         let text = input[self.0].as_str().unwrap_or_default().to_uppercase();
///         Ok(GenerateResult::from_text(text).with_tokens(TokenUsage::new(3, 2)))
///     }
///     fn input_keys(&self) -> Vec<String> {
///         vec![self.0.into()]
///     }
/// }
///
/// # tokio_test::block_on(async {
/// let log = Arc::new(Mutex::new(Vec::new()));
/// let sink = Arc::clone(&log);
/// let pipeline = SequentialChain::builder()
///     .inputs(["topic"])
///     .chain(Upper("topic"), "title")
///     .step(Step::new(Upper("text"), "shout").map_input("text", "title"))
///     .on_event(move |e| {
///         if let StepEvent::Finished { name, .. } = e {
///             sink.lock().unwrap().push(name.to_string());
///         }
///     })
///     .build()
///     .unwrap();
///
/// let run = pipeline.run(prompt_args! { "topic" => "rust" }).await.unwrap();
/// assert_eq!(run.result.generation, "RUST");
/// assert_eq!(run.usage().unwrap().total_tokens, 10);
/// assert_eq!(*log.lock().unwrap(), ["title", "shout"]);
///
/// // Wiring mistakes are caught before anything runs.
/// let broken = SequentialChain::builder()
///     .inputs(["topic"])
///     .chain(Upper("topc"), "title")
///     .build();
/// assert!(broken.is_err());
/// # });
/// ```
pub struct SequentialChain {
    steps: Vec<Step>,
    names: Vec<String>,
    inputs: Vec<String>,
    on_event: Option<EventHook>,
}

impl fmt::Debug for SequentialChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SequentialChain")
            .field("steps", &self.names)
            .field("inputs", &self.inputs)
            .finish_non_exhaustive()
    }
}

/// State threaded through a run.
struct Progress {
    vars: PromptArgs,
    outputs: HashMap<String, Value>,
    usage: Option<TokenUsage>,
    last: Option<GenerateResult>,
    reports: Vec<StepReport>,
    exited_after: Option<usize>,
}

impl SequentialChain {
    /// Start building a pipeline.
    pub fn builder() -> SequentialChainBuilder {
        SequentialChainBuilder {
            steps: Vec::new(),
            inputs: None,
            step_timeout: None,
            on_event: None,
        }
    }

    /// The steps' names, in order.
    #[must_use]
    pub fn step_names(&self) -> &[String] {
        &self.names
    }

    fn emit(&self, event: &StepEvent<'_>) {
        if let Some(hook) = &self.on_event {
            hook(event);
        }
    }

    fn check_inputs(&self, input: &PromptArgs) -> Result<(), ChainError> {
        self.inputs
            .iter()
            .find(|k| !input.contains_key(*k))
            .map_or(Ok(()), |key| Err(ChainError::MissingVariable(key.clone())))
    }

    /// Run `step` until it succeeds, its retry policy gives up, or it fails
    /// with an error the policy does not retry.
    async fn attempt(
        &self,
        index: usize,
        step: &Step,
        input: &PromptArgs,
    ) -> (
        Result<(GenerateResult, Option<HashMap<String, Value>>), ChainError>,
        u32,
    ) {
        let name = self.names[index].as_str();
        let mut attempt = 1u32;
        loop {
            let error = match step.run_once(name, input.clone()).await {
                Ok(done) => return (Ok(done), attempt),
                Err(error) => error,
            };
            let Some(policy) = step
                .retry
                .as_ref()
                .filter(|p| p.should_retry(&error, attempt))
            else {
                return (Err(error), attempt);
            };
            let delay = policy.delay(&error, attempt);
            self.emit(&StepEvent::Retrying {
                index,
                name,
                attempt,
                error: &error,
                delay,
            });
            tokio::time::sleep(delay).await;
            attempt = attempt.saturating_add(1);
        }
    }

    /// Run the first `count` steps.
    async fn run_steps(&self, input: PromptArgs, count: usize) -> Result<Progress, ChainError> {
        self.check_inputs(&input)?;
        let mut p = Progress {
            vars: input,
            outputs: HashMap::new(),
            usage: None,
            last: None,
            reports: Vec::new(),
            exited_after: None,
        };
        for (index, step) in self.steps.iter().enumerate().take(count) {
            let name = self.names[index].as_str();
            self.emit(&StepEvent::Started { index, name });
            let started = Instant::now();
            let step_input = step.input_for(&p.vars);
            let (outcome, attempts) = self.attempt(index, step, &step_input).await;
            let stored = outcome.and_then(|(result, map)| {
                let mut writes = Vec::with_capacity(step.outputs.len() + 1);
                for (key, to) in &step.outputs {
                    let value =
                        map.as_ref()
                            .and_then(|m| m.get(key))
                            .cloned()
                            .ok_or_else(|| {
                                ChainError::Other(format!(
                                    "step `{name}` returned no `{key}` output"
                                ))
                            })?;
                    writes.push((to.clone(), value));
                }
                writes.push((
                    step.output_key.clone(),
                    Value::String(result.generation.clone()),
                ));
                Ok((result, writes))
            });
            let elapsed = started.elapsed();
            let (result, writes) = match stored {
                Ok(done) => done,
                Err(error) => {
                    self.emit(&StepEvent::Failed {
                        index,
                        name,
                        error: &error,
                        attempts,
                        elapsed,
                    });
                    return Err(error);
                }
            };
            for (key, value) in writes {
                p.vars.insert(key.clone(), value.clone());
                p.outputs.insert(key, value);
            }
            TokenUsage::accumulate(&mut p.usage, result.tokens.as_ref());
            self.emit(&StepEvent::Finished {
                index,
                name,
                result: &result,
                attempts,
                elapsed,
            });
            p.reports.push(StepReport {
                name: name.to_string(),
                output_key: step.output_key.clone(),
                result: result.clone(),
                attempts,
                elapsed,
            });
            let exit = step.exits_on(&result) && index + 1 < self.steps.len();
            p.last = Some(result);
            if exit {
                p.exited_after = Some(index);
                self.emit(&StepEvent::Exited { index, name });
                break;
            }
        }
        Ok(p)
    }

    /// Run the pipeline and return every step's output, a report per step,
    /// and the final result with token usage summed across steps.
    ///
    /// The declared (or inferred) inputs are checked before any step runs.
    ///
    /// # Errors
    ///
    /// [`ChainError::MissingVariable`] for a missing input, or the first
    /// step error left after retries (a timeout is an
    /// [`LlmError`](rune_chain_core::LlmError) of kind
    /// [`Timeout`](rune_chain_core::LlmErrorKind::Timeout)).
    pub async fn run(&self, input: PromptArgs) -> Result<SequentialRun, ChainError> {
        let mut p = self.run_steps(input, self.steps.len()).await?;
        let mut result = p.last.take().unwrap_or_default();
        result.tokens = p.usage;
        if let Some(stop) = p.exited_after {
            for step in &self.steps[stop + 1..] {
                for (_, to) in &step.outputs {
                    p.outputs.insert(to.clone(), Value::Null);
                }
                p.outputs.insert(step.output_key.clone(), Value::Null);
            }
        }
        p.outputs.insert(
            self.primary_output_key(),
            Value::String(result.generation.clone()),
        );
        Ok(SequentialRun {
            result,
            outputs: p.outputs,
            steps: p.reports,
            exited_after: p.exited_after.map(|i| self.names[i].clone()),
        })
    }
}

fn single_chunk(text: String) -> ChainStream {
    Box::pin(stream::iter([
        Ok(StreamData::chunk(text)),
        Ok(StreamData::done()),
    ]))
}

#[async_trait]
impl Chain for SequentialChain {
    async fn call(&self, input: PromptArgs) -> Result<GenerateResult, ChainError> {
        Ok(self.run(input).await?.result)
    }

    async fn execute(&self, input: PromptArgs) -> Result<HashMap<String, Value>, ChainError> {
        let run = self.run(input).await?;
        let mut map = run.outputs;
        map.insert(
            RESULT_KEY.to_string(),
            serde_json::to_value(&run.result)
                .map_err(|e| ChainError::Other(format!("result serialisation failed: {e}")))?,
        );
        Ok(map)
    }

    /// Run every step but the last, then stream the last step.
    ///
    /// The last step's timeout applies to opening its stream; it is not
    /// retried. After an early exit the final answer arrives as one chunk.
    async fn stream(&self, input: PromptArgs) -> Result<ChainStream, ChainError> {
        let Some(last) = self.steps.len().checked_sub(1) else {
            self.check_inputs(&input)?;
            return Ok(single_chunk(String::new()));
        };
        let p = self.run_steps(input, last).await?;
        if p.exited_after.is_some() {
            return Ok(single_chunk(p.last.unwrap_or_default().generation));
        }
        let step = &self.steps[last];
        let name = self.names[last].as_str();
        self.emit(&StepEvent::Started { index: last, name });
        let started = Instant::now();
        let open = step.chain.stream(step.input_for(&p.vars));
        let opened = match step.timeout {
            None => open.await,
            Some(limit) => tokio::time::timeout(limit, open)
                .await
                .unwrap_or_else(|_| Err(timeout_error(name, limit))),
        };
        opened.inspect_err(|error| {
            self.emit(&StepEvent::Failed {
                index: last,
                name,
                error,
                attempts: 1,
                elapsed: started.elapsed(),
            });
        })
    }

    /// The declared inputs, or the inferred ones: every variable a step
    /// needs that no earlier step produces.
    fn input_keys(&self) -> Vec<String> {
        self.inputs.clone()
    }

    /// Each step's mapped outputs and output key, in order, then
    /// `"generate_result"`.
    fn output_keys(&self) -> Vec<String> {
        let mut keys: Vec<String> = self
            .steps
            .iter()
            .flat_map(|s| {
                s.outputs
                    .iter()
                    .map(|(_, to)| to.clone())
                    .chain(std::iter::once(s.output_key.clone()))
            })
            .collect();
        keys.push(RESULT_KEY.to_string());
        keys
    }
}

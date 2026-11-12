//! Ordered pipelines of transforms.

use std::sync::Arc;

use crate::{Category, Error, Transform};

/// An ordered pipeline of transforms.
///
/// [`encode`](TransformChain::encode) runs the steps front to back;
/// [`decode`](TransformChain::decode) undoes them back to front. A chain is
/// itself a [`Transform`], so chains nest; give one a name with
/// [`with_id`](TransformChain::with_id) and it can be
/// [registered](crate::TransformRegistry::register) like any other
/// transform.
///
/// ```
/// use std::sync::Arc;
/// use rune_transform::{PrefixTransform, TransformChain, TransformRegistry};
///
/// let registry = TransformRegistry::builtin();
/// let chain = registry
///     .chain(&["url"])?
///     .then(Arc::new(PrefixTransform::new("q=")));
/// assert_eq!(chain.encode(b"a b")?, b"q=a%20b");
/// assert_eq!(chain.decode(b"q=a%20b")?, b"a b");
/// # Ok::<(), rune_transform::Error>(())
/// ```
#[derive(Debug, Clone, Default)]
pub struct TransformChain {
    /// The steps, in encode order.
    steps: Vec<Arc<dyn Transform>>,
    /// Id the chain reports as a [`Transform`]; `"chain"` when unset.
    id: Option<String>,
}

impl TransformChain {
    /// A chain of `steps`, in encode order.
    #[must_use]
    pub const fn new(steps: Vec<Arc<dyn Transform>>) -> Self {
        Self { steps, id: None }
    }

    /// Name the chain, so it can be registered as a transform of its own.
    ///
    /// ```
    /// use rune_transform::TransformRegistry;
    ///
    /// let mut registry = TransformRegistry::builtin();
    /// let triple = registry.parse_chain("url url url")?.with_id("triple_url");
    /// registry.register(triple)?;
    /// assert_eq!(registry.encode("triple_url", b" ")?, b"%252520");
    /// assert_eq!(registry.decode("triple_url", b"%252520")?, b" ");
    /// # Ok::<(), rune_transform::Error>(())
    /// ```
    #[must_use]
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    /// Append a step and return the chain.
    #[must_use]
    pub fn then(mut self, step: Arc<dyn Transform>) -> Self {
        self.steps.push(step);
        self
    }

    /// Append a step in place.
    pub fn push(&mut self, step: Arc<dyn Transform>) {
        self.steps.push(step);
    }

    /// The steps, in encode order.
    #[must_use]
    pub fn steps(&self) -> &[Arc<dyn Transform>] {
        &self.steps
    }

    /// The ids of the steps, in encode order.
    pub fn ids(&self) -> impl Iterator<Item = &str> + '_ {
        self.steps.iter().map(Transform::id)
    }

    /// Number of steps.
    #[must_use]
    pub fn len(&self) -> usize {
        self.steps.len()
    }

    /// Whether the chain has no steps (it then passes input through).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// Whether every step is reversible, so [`decode`](Self::decode) works.
    #[must_use]
    pub fn is_reversible(&self) -> bool {
        self.steps.iter().all(Transform::is_reversible)
    }

    /// Apply every step in order.
    ///
    /// # Errors
    /// Returns the first [`Error`] raised by a step.
    pub fn encode(&self, input: &[u8]) -> Result<Vec<u8>, Error> {
        let mut current = input.to_vec();
        for step in &self.steps {
            current = step.encode(&current)?;
        }
        Ok(current)
    }

    /// Reverse every step, last step first.
    ///
    /// # Errors
    /// Returns [`Error::NotReversible`] naming the first one-way step before
    /// any work is done, or the first [`Error`] raised while decoding.
    pub fn decode(&self, input: &[u8]) -> Result<Vec<u8>, Error> {
        if let Some(step) = self.steps.iter().find(|step| !step.is_reversible()) {
            return Err(Error::not_reversible(step.id()));
        }
        let mut current = input.to_vec();
        for step in self.steps.iter().rev() {
            current = step.decode(&current)?;
        }
        Ok(current)
    }

    /// Apply every step in order, keeping each intermediate output.
    ///
    /// Returns `(step id, output)` pairs, one per step, so a caller can show
    /// how a value changes along the chain.
    ///
    /// # Errors
    /// Returns the first [`Error`] raised by a step.
    pub fn trace(&self, input: &[u8]) -> Result<Vec<(String, Vec<u8>)>, Error> {
        let mut out: Vec<(String, Vec<u8>)> = Vec::with_capacity(self.steps.len());
        for step in &self.steps {
            let previous = out.last().map_or(input, |(_, bytes)| bytes.as_slice());
            let next = step.encode(previous)?;
            out.push((step.id().to_owned(), next));
        }
        Ok(out)
    }
}

impl Transform for TransformChain {
    fn id(&self) -> &str {
        self.id.as_deref().unwrap_or("chain")
    }

    fn description(&self) -> &'static str {
        "A pipeline of transforms"
    }

    fn category(&self) -> Category {
        Category::Other
    }

    fn is_reversible(&self) -> bool {
        Self::is_reversible(self)
    }

    fn encode(&self, input: &[u8]) -> Result<Vec<u8>, Error> {
        Self::encode(self, input)
    }

    fn decode(&self, input: &[u8]) -> Result<Vec<u8>, Error> {
        Self::decode(self, input)
    }
}

impl FromIterator<Arc<dyn Transform>> for TransformChain {
    fn from_iter<I: IntoIterator<Item = Arc<dyn Transform>>>(iter: I) -> Self {
        Self::new(iter.into_iter().collect())
    }
}

impl Extend<Arc<dyn Transform>> for TransformChain {
    fn extend<I: IntoIterator<Item = Arc<dyn Transform>>>(&mut self, iter: I) {
        self.steps.extend(iter);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PrefixTransform, SuffixTransform, TransformRegistry};

    #[test]
    fn empty_chain_passes_through() {
        let chain = TransformChain::default();
        assert!(chain.is_empty());
        assert!(chain.is_reversible());
        assert_eq!(chain.encode(b"x").ok(), Some(b"x".to_vec()));
        assert_eq!(chain.decode(b"x").ok(), Some(b"x".to_vec()));
    }

    #[test]
    fn decode_refuses_one_way_chain_up_front() {
        let registry = TransformRegistry::builtin();
        let chain = registry.chain(&["sha256", "hex"]).ok();
        let chain = chain.as_ref();
        assert_eq!(chain.map(TransformChain::len), Some(2));
        assert_eq!(
            chain.and_then(|c| c.decode(b"00").err()),
            Some(Error::not_reversible("sha256"))
        );
    }

    #[test]
    fn trace_records_every_step_and_chains_nest() {
        let mut chain: TransformChain = [
            Arc::new(PrefixTransform::new("<")) as Arc<dyn Transform>,
            Arc::new(SuffixTransform::new(">")),
        ]
        .into_iter()
        .collect();
        chain.extend([Arc::new(PrefixTransform::new("!")) as Arc<dyn Transform>]);
        let trace = chain.trace(b"a").ok();
        assert_eq!(
            trace,
            Some(vec![
                ("prefix".to_owned(), b"<a".to_vec()),
                ("suffix".to_owned(), b"<a>".to_vec()),
                ("prefix".to_owned(), b"!<a>".to_vec()),
            ])
        );
        assert_eq!(
            chain.ids().collect::<Vec<_>>(),
            ["prefix", "suffix", "prefix"]
        );

        let mut outer = TransformChain::default();
        outer.push(Arc::new(chain));
        assert_eq!(outer.steps()[0].id(), "chain");
        assert_eq!(outer.encode(b"a").ok(), Some(b"!<a>".to_vec()));
        assert_eq!(outer.decode(b"!<a>").ok(), Some(b"a".to_vec()));
    }
}

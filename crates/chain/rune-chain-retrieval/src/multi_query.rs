use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use futures::future::try_join_all;
use rune_chain_core::{Llm, Message};

use crate::error::{RetrievalError, check_non_negative};
use crate::fusion::{DEFAULT_RRF_K, reciprocal_rank_fusion};
use crate::retriever::Retriever;
use crate::scored::ScoredDocument;

/// Longest query variant kept, in characters; longer lines are truncated.
const MAX_VARIANT_CHARS: usize = 1_000;

const DEFAULT_PROMPT: &str = "You are an AI assistant helping a search engine. \
Write {n} different rephrasings of the user's question that could retrieve relevant \
documents from a vector or keyword index. Vary wording and perspective. \
Output one rephrasing per line, with no numbering and no other text.";

/// Retriever that asks an [`Llm`] for alternative phrasings of the query,
/// retrieves for each (and the original), and fuses the lists with
/// [`reciprocal_rank_fusion`].
///
/// The model's reply is parsed leniently: one variant per line, list
/// markers (`1.`, `2)`, `-`, `*`, `•`) and surrounding quotes stripped,
/// blank and duplicate lines dropped, at most `num_queries` kept, each
/// capped at 1 000 characters. If the model fails, the error is returned;
/// if it returns no usable line, only the original query is used.
///
/// ```rust
/// use std::sync::Arc;
/// use async_trait::async_trait;
/// use rune_chain_core::{GenerateResult, Llm, LlmError, Message};
/// use rune_chain_retrieval::{Bm25Retriever, Document, MultiQueryRetriever, Retriever};
///
/// struct Variants;
/// #[async_trait]
/// impl Llm for Variants {
///     async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
///         Ok(GenerateResult::from_text("1. borrow checker\n2. ownership rules"))
///     }
/// }
///
/// # tokio_test::block_on(async {
/// let base = Arc::new(Bm25Retriever::from_documents(vec![
///     Document::new("The borrow checker enforces ownership rules."),
///     Document::new("Garbage collection in Java."),
/// ]));
/// let retriever = MultiQueryRetriever::new(Variants, base);
/// let hits = retriever.retrieve("how does rust manage memory", 1).await?;
/// assert!(hits[0].document.content.contains("borrow checker"));
/// # Ok::<(), rune_chain_retrieval::RetrievalError>(())
/// # }).unwrap();
/// ```
pub struct MultiQueryRetriever<L> {
    llm: L,
    retriever: Arc<dyn Retriever>,
    num_queries: usize,
    include_original: bool,
    rrf_k: f32,
    prompt: String,
}

impl<L> std::fmt::Debug for MultiQueryRetriever<L> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiQueryRetriever")
            .field("num_queries", &self.num_queries)
            .field("include_original", &self.include_original)
            .field("rrf_k", &self.rrf_k)
            .finish_non_exhaustive()
    }
}

impl<L: Llm> MultiQueryRetriever<L> {
    /// Three variants plus the original query, fused with RRF `k = 60`.
    pub fn new(llm: L, retriever: Arc<dyn Retriever>) -> Self {
        Self {
            llm,
            retriever,
            num_queries: 3,
            include_original: true,
            rrf_k: DEFAULT_RRF_K,
            prompt: DEFAULT_PROMPT.to_owned(),
        }
    }

    /// How many variants to request and keep.
    #[must_use]
    pub const fn with_num_queries(mut self, n: usize) -> Self {
        self.num_queries = n;
        self
    }

    /// Whether the original query is searched too (default `true`).
    #[must_use]
    pub const fn include_original(mut self, include: bool) -> Self {
        self.include_original = include;
        self
    }

    /// RRF `k` for fusing the per-query lists.
    ///
    /// # Errors
    ///
    /// [`RetrievalError::InvalidArgument`] if `k` is negative or not finite.
    pub fn with_rrf_k(mut self, k: f32) -> Result<Self, RetrievalError> {
        self.rrf_k = check_non_negative("rrf k", k)?;
        Ok(self)
    }

    /// Replace the system prompt; `{n}` is replaced by the variant count.
    /// The user's query is sent as the human message.
    #[must_use]
    pub fn with_prompt(mut self, prompt: impl Into<String>) -> Self {
        self.prompt = prompt.into();
        self
    }

    /// Ask the LLM for query variants (parsed as described on the type).
    pub async fn generate_queries(&self, query: &str) -> Result<Vec<String>, RetrievalError> {
        if self.num_queries == 0 {
            return Ok(Vec::new());
        }
        let system = self.prompt.replace("{n}", &self.num_queries.to_string());
        let reply = self
            .llm
            .generate(&[Message::system(system), Message::human(query)])
            .await?;
        Ok(parse_query_variants(&reply.generation, self.num_queries))
    }
}

/// Parse an LLM reply into at most `max` distinct, non-empty query lines.
#[must_use]
pub fn parse_query_variants(reply: &str, max: usize) -> Vec<String> {
    let mut seen = HashSet::new();
    reply
        .lines()
        .map(strip_list_marker)
        .map(|l| l.trim_matches(|c: char| c == '"' || c == '\'' || c.is_whitespace()))
        .filter(|l| !l.is_empty())
        .map(|l| l.chars().take(MAX_VARIANT_CHARS).collect::<String>())
        .filter(|l| seen.insert(l.to_lowercase()))
        .take(max)
        .collect()
}

fn strip_list_marker(line: &str) -> &str {
    let line = line.trim_start();
    let line = line.strip_prefix(['-', '*', '•']).unwrap_or_else(|| {
        let digits = line.chars().take_while(char::is_ascii_digit).count();
        if digits > 0 {
            line[digits..].strip_prefix(['.', ')', ':']).unwrap_or(line)
        } else {
            line
        }
    });
    line.trim_start()
}

#[async_trait]
impl<L: Llm> Retriever for MultiQueryRetriever<L> {
    async fn retrieve(
        &self,
        query: &str,
        top_k: usize,
    ) -> Result<Vec<ScoredDocument>, RetrievalError> {
        if top_k == 0 {
            return Ok(Vec::new());
        }
        let mut queries = Vec::with_capacity(self.num_queries + 1);
        if self.include_original {
            queries.push(query.to_owned());
        }
        for variant in self.generate_queries(query).await? {
            if !queries.iter().any(|q| q.eq_ignore_ascii_case(&variant)) {
                queries.push(variant);
            }
        }
        if queries.is_empty() {
            queries.push(query.to_owned());
        }
        let lists = try_join_all(queries.iter().map(|q| self.retriever.retrieve(q, top_k))).await?;
        let mut fused = reciprocal_rank_fusion(&lists, &[], self.rrf_k)?;
        fused.truncate(top_k);
        Ok(fused)
    }
}

#[cfg(test)]
#[allow(clippy::assert_is_empty, reason = "emptiness is the expectation")]
mod tests {
    use super::*;

    #[test]
    fn parses_numbered_bulleted_and_quoted_lines() {
        let reply =
            "1. first query\n2) second\n- third\n* \"fourth\"\n\n• fifth\n10: tenth\nFIRST QUERY";
        assert_eq!(
            parse_query_variants(reply, 10),
            ["first query", "second", "third", "fourth", "fifth", "tenth"]
        );
        assert_eq!(parse_query_variants(reply, 2).len(), 2);
        assert!(parse_query_variants("", 3).is_empty());
        assert!(parse_query_variants("x", 0).is_empty());
    }

    #[test]
    fn keeps_numbers_that_are_not_markers() {
        assert_eq!(parse_query_variants("2024 results", 1), ["2024 results"]);
    }

    #[test]
    fn caps_line_length() {
        let long = "é".repeat(5_000);
        assert_eq!(
            parse_query_variants(&long, 1)[0].chars().count(),
            MAX_VARIANT_CHARS
        );
    }
}

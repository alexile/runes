//! Runtime behaviour of `#[derive(Embed)]` and one-call ingestion.

use std::borrow::Cow;

use async_trait::async_trait;
use rune_chain_embed::{Embed, EmbedError, Embedder, VectorStoreExt, to_records};
use rune_vectorstore::{InMemoryVectorStore, Options, Query, VectorStore};
use serde::Serialize;

#[derive(Embed, Serialize)]
struct Article {
    #[embed_id]
    slug: String,
    #[embed]
    title: String,
    #[embed]
    paragraphs: Vec<String>,
    year: u16,
}

#[derive(Embed, Serialize)]
struct Note<'a> {
    #[embed]
    body: &'a str,
    #[embed]
    summary: Option<Cow<'a, str>>,
}

#[derive(Embed)]
struct Pair(#[embed] String, #[allow(dead_code)] u8, #[embed] Box<str>);

#[derive(Embed)]
struct Generic<T: rune_chain_embed::EmbedText> {
    #[embed]
    inner: T,
    #[embed_id]
    id: u32,
}

/// Embeds a text as `[letter count, 1]`.
struct Letters;

#[async_trait]
impl Embedder for Letters {
    async fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError> {
        Ok(texts
            .iter()
            .map(|t| {
                let n = t.chars().filter(|c| c.is_alphabetic()).count();
                vec![f32::from(u16::try_from(n).unwrap_or(u16::MAX)), 1.0]
            })
            .collect())
    }
}

fn article(slug: &str, title: &str, paragraphs: &[&str]) -> Article {
    Article {
        slug: slug.into(),
        title: title.into(),
        paragraphs: paragraphs.iter().map(|&p| p.to_owned()).collect(),
        year: 2025,
    }
}

#[test]
fn derive_collects_marked_fields_in_order() {
    let a = article("intro", "Hello", &["one", "two"]);
    assert_eq!(a.texts(), ["Hello", "one", "two"]);
    assert_eq!(a.embed_id().as_deref(), Some("intro"));

    let n = Note {
        body: "body",
        summary: None,
    };
    assert_eq!(n.texts(), ["body"]);
    assert_eq!(n.embed_id(), None);
    let n = Note {
        body: "body",
        summary: Some(Cow::Borrowed("short")),
    };
    assert_eq!(n.texts(), ["body", "short"]);

    let p = Pair("left".into(), 0, "right".into());
    assert_eq!(p.texts(), ["left", "right"]);

    let g = Generic {
        inner: vec!["a", "b"],
        id: 9,
    };
    assert_eq!(g.texts(), ["a", "b"]);
    assert_eq!(g.embed_id().as_deref(), Some("9"));
}

#[tokio::test]
async fn records_carry_ids_content_and_metadata() {
    let docs = [
        article("a", "Rust", &[]),
        article("b", "Go", &["Gophers", ""]),
    ];
    let records = to_records(&Letters, &docs).await.unwrap();
    let ids: Vec<&str> = records.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(ids, ["a", "b#0", "b#1"]);
    assert_eq!(records[2].content, "Gophers");
    assert_eq!(records[2].vector, [7.0, 1.0]);
    assert_eq!(records[2].metadata["slug"], "b");
    assert_eq!(records[2].metadata["year"], 2025);
}

#[tokio::test]
async fn one_call_ingestion_then_search() {
    let store = InMemoryVectorStore::new(Options::default().with_dimension(2));
    let docs = vec![
        article("short", "Hi", &[]),
        article("long", "Extraordinarily", &[]),
    ];
    assert_eq!(store.add_documents(&Letters, &docs).await.unwrap(), 2);
    assert_eq!(store.len().await.unwrap(), 2);

    // Re-adding replaces instead of duplicating.
    assert_eq!(store.add_documents(&Letters, &docs).await.unwrap(), 2);
    assert_eq!(store.len().await.unwrap(), 2);

    let q = Letters.embed_query("Hey").await.unwrap();
    let hits = store
        .query(&Query::new(q, 1).with_vectors(false))
        .await
        .unwrap();
    assert_eq!(hits[0].record.id, "short");

    // Plain strings are documents too.
    assert_eq!(
        store.add_documents(&Letters, &["abc", " "]).await.unwrap(),
        1
    );
    assert_eq!(store.len().await.unwrap(), 3);
}

//! HNSW store with metadata filters, MMR and a snapshot round trip.
//!
//! Run with `cargo run -p rune-vectorstore --example quickstart`.

#![allow(clippy::print_stdout, reason = "an example prints its results")]

use rune_vectorstore::{
    Filter, HnswParams, InMemoryVectorStore, IndexKind, LoadLimits, Metric, Options, Query, Record,
    StoreError, VectorStore,
};

/// Toy "embedding": a few hand-made features per text.
fn embed(text: &str) -> Vec<f32> {
    let t = text.to_lowercase();
    let has = |w: &str| if t.contains(w) { 1.0 } else { 0.0 };
    vec![
        has("rust"),
        has("memory"),
        has("python"),
        has("capital"),
        0.1,
    ]
}

#[tokio::main]
async fn main() -> Result<(), StoreError> {
    let store = InMemoryVectorStore::new(
        Options::default()
            .with_metric(Metric::Cosine)
            .with_index(IndexKind::Hnsw(HnswParams::default())),
    );

    let docs = [
        (
            "d1",
            "Rust guarantees memory safety without a GC.",
            "lang",
            2015,
        ),
        (
            "d2",
            "Rust ownership rules prevent memory bugs.",
            "lang",
            2018,
        ),
        ("d3", "Python is dynamically typed.", "lang", 1991),
        ("d4", "Paris is the capital of France.", "geo", 2020),
    ];
    store
        .upsert(
            docs.iter()
                .map(|(id, text, topic, year)| {
                    Record::new(*id, embed(text))
                        .with_content(*text)
                        .with_meta("topic", *topic)
                        .with_meta("year", *year)
                })
                .collect(),
        )
        .await?;

    let q = embed("rust memory");
    println!("nearest:");
    for hit in store.query(&Query::new(q.clone(), 2)).await? {
        println!("  {:.3}  {}", hit.score, hit.record.content);
    }

    let filtered = Query::new(q.clone(), 3)
        .with_filter(Filter::eq("topic", "lang").and(Filter::lt("year", 2017)));
    println!("lang before 2017:");
    for hit in store.query(&filtered).await? {
        println!("  {:.3}  {}", hit.score, hit.record.content);
    }

    println!("diverse (MMR, lambda 0.3):");
    for hit in store
        .query_mmr(&Query::new(q.clone(), 2), 4, 0.3, Metric::Cosine)
        .await?
    {
        println!("  {:.3}  {}", hit.score, hit.record.content);
    }

    let path = std::env::temp_dir().join(format!("vectorstore-example-{}.bin", std::process::id()));
    store.save(&path)?;
    let restored = InMemoryVectorStore::load(&path, &LoadLimits::default())?;
    println!(
        "restored {} records from {}",
        restored.len().await?,
        path.display()
    );
    std::fs::remove_file(&path)?;
    Ok(())
}

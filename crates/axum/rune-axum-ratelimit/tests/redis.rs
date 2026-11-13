//! Runs the Redis store's Lua scripts against a real server.
//!
//! These tests need a disposable Redis (6.2 or newer) and are skipped unless `REDIS_URL` is
//! set, e.g.:
//!
//! ```text
//! docker run --rm -d -p 6379:6379 redis:7
//! REDIS_URL=redis://127.0.0.1:6379/ cargo test -p rune-axum-ratelimit --features redis
//! ```
//!
//! Each test uses its own key prefix. One test runs `SCRIPT FLUSH`, so don't point
//! `REDIS_URL` at a server that matters.
#![cfg(feature = "redis")]
#![allow(clippy::expect_used, reason = "test helpers fail loudly")]

use redis::aio::ConnectionManager;
use rune_axum_ratelimit::redis::RedisStore;
use rune_axum_ratelimit::store::{Algorithm, Quota, RateLimitStore};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const SEC: Duration = Duration::from_secs(1);

async fn server(test: &str) -> Option<(RedisStore, ConnectionManager, String)> {
    let Ok(url) = std::env::var("REDIS_URL") else {
        eprintln!("REDIS_URL not set; skipping {test}");
        return None;
    };
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let prefix = format!("rl-test:{test}:{}:{nanos}", std::process::id());
    let store = RedisStore::connect(&url)
        .await
        .expect("connect to REDIS_URL")
        .prefix(prefix.clone());
    let client = redis::Client::open(url).expect("valid REDIS_URL");
    let conn = ConnectionManager::new(client).await.expect("connect");
    Some((store, conn, prefix))
}

async fn pttl(conn: &mut ConnectionManager, key: &str) -> i64 {
    redis::cmd("PTTL")
        .arg(key)
        .query_async(conn)
        .await
        .expect("PTTL")
}

#[tokio::test]
async fn gcra_burst_then_deny() {
    let Some((store, mut conn, _)) = server("gcra").await else {
        return;
    };
    let q = Quota::new(4, 4 * SEC, Algorithm::Gcra);
    for expected in [3, 2, 1, 0] {
        let d = store.check("ip:192.0.2.1", &q).await.expect("check");
        assert!(d.allowed);
        assert_eq!(d.remaining, expected);
    }
    let d = store.check("ip:192.0.2.1", &q).await.expect("check");
    assert!(!d.allowed);
    let retry = d.retry_after.expect("retry-after");
    assert!(retry > Duration::ZERO && retry <= SEC, "{retry:?}");
    assert!(d.reset <= 4 * SEC);

    // Another client is unaffected.
    assert!(
        store
            .check("ip:192.0.2.2", &q)
            .await
            .expect("check")
            .allowed
    );

    // The key expires once the quota is restored.
    let ttl = pttl(&mut conn, &store.redis_key("ip:192.0.2.1", Algorithm::Gcra)).await;
    assert!(ttl > 0 && ttl <= 4_000, "{ttl}");

    // After one interval a token is back.
    tokio::time::sleep(retry + Duration::from_millis(20)).await;
    assert!(
        store
            .check("ip:192.0.2.1", &q)
            .await
            .expect("check")
            .allowed
    );
}

#[tokio::test]
async fn fixed_window_counts_and_expires() {
    let Some((store, mut conn, _)) = server("fw").await else {
        return;
    };
    let q = Quota::new(3, Duration::from_millis(300), Algorithm::FixedWindow);
    for expected in [2, 1, 0] {
        let d = store.check("k", &q).await.expect("check");
        assert!(d.allowed);
        assert_eq!(d.remaining, expected);
    }
    let d = store.check("k", &q).await.expect("check");
    assert!(!d.allowed);
    assert!(d.retry_after.expect("retry-after") <= Duration::from_millis(300));

    let key = store.redis_key("k", Algorithm::FixedWindow);
    let ttl = pttl(&mut conn, &key).await;
    assert!(ttl > 0 && ttl <= 300, "{ttl}");
    // Denied requests don't inflate the counter.
    let count: i64 = redis::cmd("GET")
        .arg(&key)
        .query_async(&mut conn)
        .await
        .expect("GET");
    assert_eq!(count, 3);

    tokio::time::sleep(Duration::from_millis(350)).await;
    let d = store.check("k", &q).await.expect("check");
    assert!(d.allowed);
    assert_eq!(d.remaining, 2);
}

#[tokio::test]
async fn counter_without_ttl_is_repaired() {
    let Some((store, mut conn, _)) = server("repair").await else {
        return;
    };
    let q = Quota::new(2, 10 * SEC, Algorithm::FixedWindow);
    let key = store.redis_key("k", Algorithm::FixedWindow);
    let () = redis::cmd("SET")
        .arg(&key)
        .arg(99)
        .query_async(&mut conn)
        .await
        .expect("SET");
    let d = store.check("k", &q).await.expect("check");
    assert!(d.allowed);
    assert_eq!(d.remaining, 1);
    assert!(pttl(&mut conn, &key).await > 0);
}

#[tokio::test]
async fn hashed_keys_hide_client_ips() {
    let Some((store, mut conn, prefix)) = server("hashed").await else {
        return;
    };
    let store = store.hash_keys(b"test secret");
    let q = Quota::new(5, 10 * SEC, Algorithm::Gcra);
    store.check("ip:198.51.100.23", &q).await.expect("check");
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg(format!("{prefix}:*"))
        .query_async(&mut conn)
        .await
        .expect("KEYS");
    assert_eq!(keys.len(), 1);
    assert!(!keys[0].contains("198.51.100.23"));
    assert_eq!(
        keys[0],
        store.redis_key("ip:198.51.100.23", Algorithm::Gcra)
    );
}

#[tokio::test]
async fn reloads_scripts_after_flush() {
    let Some((store, mut conn, _)) = server("noscript").await else {
        return;
    };
    let q = Quota::new(5, 10 * SEC, Algorithm::Gcra);
    assert!(store.check("k", &q).await.expect("check").allowed);
    let () = redis::cmd("SCRIPT")
        .arg("FLUSH")
        .query_async(&mut conn)
        .await
        .expect("SCRIPT FLUSH");
    let d = store.check("k", &q).await.expect("falls back to EVAL");
    assert_eq!(d.remaining, 3);
}

#[tokio::test]
async fn instances_share_the_limit() {
    let Some((a, _, prefix)) = server("shared").await else {
        return;
    };
    let url = std::env::var("REDIS_URL").expect("set");
    let b = RedisStore::connect(&url)
        .await
        .expect("connect")
        .prefix(prefix);
    let q = Quota::new(4, 10 * SEC, Algorithm::Gcra);
    let mut allowed = 0;
    for i in 0..8 {
        let store = if i % 2 == 0 { &a } else { &b };
        allowed += u32::from(store.check("k", &q).await.expect("check").allowed);
    }
    assert_eq!(allowed, 4);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_checks_are_atomic() {
    let Some((store, _, _)) = server("atomic").await else {
        return;
    };
    for algorithm in [Algorithm::FixedWindow, Algorithm::Gcra] {
        let q = Quota::new(10, 60 * SEC, algorithm);
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..50 {
            let store = store.clone();
            tasks.spawn(async move { store.check("k", &q).await.expect("check").allowed });
        }
        let allowed = tasks.join_all().await.into_iter().filter(|a| *a).count();
        assert_eq!(allowed, 10, "{algorithm:?}");
    }
}

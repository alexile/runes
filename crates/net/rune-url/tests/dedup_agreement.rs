//! The crawler and the site map must agree on the dedup key.
//!
//! The crawler discovers URLs as `href`s relative to the page it is on and
//! resolves them; the site map receives absolute URLs (from `sitemap.xml`,
//! redirects, user input) in whatever spelling. Both key with
//! `KeyOptions::default()`. Every spelling of one resource must land on one
//! key, and different resources on different keys.

use std::collections::{BTreeMap, BTreeSet};

use rune_url::{DedupKey, Error, KeyOptions, Options, Url, dedup_key, dedup_key_url, resolve};

/// What the crawler sees: (page URL, href found on it).
const CRAWLED: &[(&str, &str)] = &[
    ("https://shop.example.com/", "/products?page=2&sort=asc"),
    (
        "https://shop.example.com/products/",
        "../products?sort=asc&page=2#grid",
    ),
    (
        "https://shop.example.com/a/b/",
        "../../products?utm_source=nl&page=2&sort=asc",
    ),
    ("https://shop.example.com/", "item/%7e42"),
    (
        "https://shop.example.com/x",
        "//SHOP.example.com:443/item/~42",
    ),
    ("https://shop.example.com/", "./about/"),
    ("https://shop.example.com/", "/about/?"),
    (
        "https://shop.example.com/",
        "https://shop.example.com./about/#team",
    ),
    (
        "https://shop.example.com/",
        "/login?next=%2Fcart&fbclid=abc",
    ),
];

/// What the site map holds, as absolute URLs, in the same order of
/// resources.
const SITE_MAP: &[&str] = &[
    "https://shop.example.com/products?sort=asc&page=2",
    "HTTPS://Shop.Example.com/products/../products?page=2&sort=asc",
    "https://shop.example.com/products?page=2&sort=asc&gclid=x",
    "https://shop.example.com/item/%7E42",
    "https://shop.example.com/item/~42",
    "https://shop.example.com/about/",
    "https://shop.example.com:443/about/",
    "https://shop.example.com/about/#",
    "https://shop.example.com/login?next=%2fcart",
];

/// Resource index of each row above (rows with the same index are the same
/// resource).
const RESOURCE: &[usize] = &[0, 0, 0, 1, 1, 2, 2, 2, 3];

fn crawler_key(page: &str, href: &str, options: &KeyOptions) -> Result<DedupKey, Error> {
    let page = Url::parse(page)?;
    let link = resolve(&page, href, &Options::crawler())?;
    Ok(dedup_key_url(&link, options))
}

fn site_map_key(url: &str, options: &KeyOptions) -> Result<DedupKey, Error> {
    dedup_key(url, options)
}

#[test]
fn crawler_and_site_map_agree() {
    let options = KeyOptions::default();
    let mut by_resource: BTreeMap<usize, BTreeSet<DedupKey>> = BTreeMap::new();
    for (index, ((page, href), absolute)) in CRAWLED.iter().zip(SITE_MAP).enumerate() {
        let crawled = crawler_key(page, href, &options).unwrap();
        let mapped = site_map_key(absolute, &options).unwrap();
        assert_eq!(
            crawled, mapped,
            "row {index}: {page} + {href} vs {absolute}"
        );
        by_resource
            .entry(RESOURCE[index])
            .or_default()
            .insert(crawled);
        by_resource
            .entry(RESOURCE[index])
            .or_default()
            .insert(mapped);
    }
    // One key per resource, and no two resources share a key.
    let mut all = BTreeSet::new();
    for (resource, keys) in &by_resource {
        assert_eq!(keys.len(), 1, "resource {resource} has keys {keys:?}");
        assert!(all.insert(keys.iter().next().unwrap().clone()));
    }
    assert_eq!(
        by_resource
            .values()
            .flatten()
            .map(DedupKey::as_str)
            .collect::<Vec<_>>(),
        [
            "https://shop.example.com/products?page=2&sort=asc",
            "https://shop.example.com/item/~42",
            "https://shop.example.com/about/",
            "https://shop.example.com/login?next=%2Fcart",
        ]
    );
}

#[test]
fn distinct_resources_stay_distinct() {
    let options = KeyOptions::default();
    let distinct = [
        "https://shop.example.com/products?page=2",
        "https://shop.example.com/products?page=3",
        "https://shop.example.com/Products?page=2",
        "http://shop.example.com/products?page=2",
        "https://shop.example.com:8443/products?page=2",
        "https://www.shop.example.com/products?page=2",
        "https://shop.example.com/products/?page=2",
        "https://shop.example.com/products?page=2&page=3",
        "https://shop.example.com/products?page=3&page=2",
        "https://shop.example.com/item/%2F42",
        "https://shop.example.com/item//42",
    ];
    let keys: BTreeSet<_> = distinct
        .iter()
        .map(|url| site_map_key(url, &options).unwrap())
        .collect();
    assert_eq!(keys.len(), distinct.len());
}

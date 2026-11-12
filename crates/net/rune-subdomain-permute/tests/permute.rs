//! End-to-end generation: determinism, deduplication, bounds, and feeding
//! candidates through `rune-wildcard-dns`. No network.

#![allow(clippy::unwrap_used, reason = "test code")]

use std::collections::HashSet;
use std::convert::Infallible;
use std::net::Ipv4Addr;

use rune_dns_wire::{Name, RData, Record, RecordType};
use rune_subdomain_permute::{Error, Options, Payloads, Permutator, Seed};
use rune_wildcard_dns::{Response, Verdict, WildcardFilter, from_fn};

fn seeds(hosts: &[&str]) -> Vec<Seed> {
    hosts.iter().map(|h| Seed::parse(h).unwrap()).collect()
}

#[test]
fn defaults_are_deterministic_and_deduplicated() {
    let seeds = seeds(&[
        "api.example.com",
        "db01.eu.example.com",
        "www.example.com",
        "api.example.com",
    ]);
    let permutator = Permutator::default();
    let first: Vec<String> = permutator.permute(&seeds).collect();
    let second: Vec<String> = permutator.permute(&seeds).collect();
    assert_eq!(first, second);

    let unique: HashSet<&String> = first.iter().collect();
    assert_eq!(unique.len(), first.len(), "no duplicates");
    for seed in &seeds {
        assert!(
            !unique.contains(&seed.name().to_owned()),
            "seed {} emitted",
            seed.name()
        );
    }
    assert!(first.len() as u64 <= permutator.estimate(&seeds));

    for expected in [
        "dev-api.example.com",
        "api-dev.example.com",
        "dev.api.example.com",
        "api.dev.example.com",
        "devapi.example.com",
        "api-staging.example.com",
        "us-east-1.api.example.com",
        "api1.example.com",
        "api-1.example.com",
        "db00.eu.example.com",
        "db02.eu.example.com",
        "prod-db01.eu.example.com",
    ] {
        assert!(unique.contains(&expected.to_owned()), "missing {expected}");
    }
    // Dot-insertion collapses duplicates across patterns: `dev` is both a
    // word and an env, yet `api-dev.example.com` appears once.
    assert_eq!(
        first.iter().filter(|c| *c == "api-dev.example.com").count(),
        1
    );
}

#[test]
fn limit_bounds_the_stream() {
    let seeds = seeds(&["api.example.com"]);
    let permutator = Permutator::with_options(Options::default().with_limit(7));
    let got: Vec<String> = permutator.permute(&seeds).collect();
    assert_eq!(got.len(), 7);
    let unbounded: Vec<String> = Permutator::default().permute(&seeds).take(7).collect();
    assert_eq!(got, unbounded, "the limit truncates, it does not reorder");
}

#[test]
fn root_seeds_skip_sub_patterns() {
    let mut payloads = Payloads::new();
    payloads.insert("word", ["dev"]).unwrap();
    let permutator = Permutator::new(
        [
            "{{word}}-{{sub}}.{{suffix}}",
            "{{word}}.{{root}}",
            "{{sld}}-{{word}}.{{etld}}",
        ],
        payloads,
        Options::default(),
    )
    .unwrap();
    let got: Vec<String> = permutator.permute(&seeds(&["example.co.uk"])).collect();
    assert_eq!(got, ["dev.example.co.uk", "example-dev.co.uk"]);
}

#[test]
fn multi_label_subs_and_indexed_vars() {
    let mut payloads = Payloads::new();
    payloads.insert("word", ["x"]).unwrap();
    let permutator = Permutator::new(
        ["{{sub}}-{{sub1}}.{{root}}", "{{sub}}.{{word}}.{{suffix}}"],
        payloads,
        Options::default(),
    )
    .unwrap();
    let got: Vec<String> = permutator
        .permute(&seeds(&["cloud.api.example.com", "www.example.com"]))
        .collect();
    assert_eq!(
        got,
        [
            "cloud-api.example.com",
            "cloud.x.api.example.com",
            "www.x.example.com"
        ]
    );
}

#[test]
fn invalid_candidates_are_dropped() {
    let mut payloads = Payloads::new();
    payloads
        .insert(
            "word",
            ["ok", "-bad", "under_score", "a".repeat(70).as_str()],
        )
        .unwrap();
    let permutator = Permutator::new(
        ["{{word}}.{{root}}", "{{word}}{{sub}}.{{root}}"],
        payloads,
        Options::default(),
    )
    .unwrap();
    let got: Vec<String> = permutator.permute(&seeds(&["www.example.com"])).collect();
    assert_eq!(got, ["ok.example.com", "okwww.example.com"]);
}

#[test]
fn enrichment_reuses_seed_tokens() {
    let mut payloads = Payloads::new();
    payloads.insert("word", ["dev"]).unwrap();
    let permutator = Permutator::new(
        ["{{word}}.{{root}}"],
        payloads,
        Options::default().with_enrich(true).with_number_delta(0),
    )
    .unwrap();
    let got: Vec<String> = permutator
        .permute(&seeds(&["payments-api.example.com"]))
        .collect();
    assert_eq!(
        got,
        ["dev.example.com", "payments.example.com", "api.example.com",]
    );
}

#[test]
fn unknown_variables_are_rejected() {
    let err =
        Permutator::new(["{{colour}}.{{root}}"], Payloads::new(), Options::default()).unwrap_err();
    assert!(matches!(err, Error::UnknownVariable { ref name, .. } if name == "colour"));
    // Conventional names may be absent: the pattern just yields nothing.
    let permutator =
        Permutator::new(["{{region}}.{{root}}"], Payloads::new(), Options::default()).unwrap();
    assert_eq!(permutator.permute(&seeds(&["example.com"])).count(), 0);
}

#[test]
fn custom_payloads_and_repeated_variables() {
    let mut payloads = Payloads::new();
    payloads.insert("team", ["red", "blue"]).unwrap();
    let permutator = Permutator::new(
        ["{{team}}.{{team}}-{{sub}}.{{root}}"],
        payloads,
        Options::default(),
    )
    .unwrap();
    let got: Vec<String> = permutator.permute(&seeds(&["ops.example.org"])).collect();
    assert_eq!(
        got,
        ["red.red-ops.example.org", "blue.blue-ops.example.org"]
    );
}

#[test]
fn candidates_feed_wildcard_filtering() {
    // `*.example.com` answers 192.0.2.1; only `dev-api` really exists.
    let real: Name = "dev-api.example.com".parse().unwrap();
    let apex: Name = "example.com".parse().unwrap();
    let mut resolver = from_fn(|name: &Name, rtype: RecordType| {
        let addr = if name.eq_ignore_ascii_case(&real) {
            Ipv4Addr::new(192, 0, 2, 50)
        } else if name.is_subdomain_of(&apex) {
            Ipv4Addr::new(192, 0, 2, 1)
        } else {
            return Ok::<_, Infallible>(Response::nxdomain());
        };
        Ok(if rtype == RecordType::A {
            Response::answer(vec![Record::new(name.clone(), 60, RData::A(addr))])
        } else {
            Response::answer(vec![])
        })
    });

    let mut payloads = Payloads::new();
    payloads.insert("word", ["dev", "test", "old"]).unwrap();
    let permutator = Permutator::new(
        ["{{word}}-{{sub}}.{{suffix}}"],
        payloads,
        Options::default(),
    )
    .unwrap();
    let mut filter = WildcardFilter::default();
    let live: Vec<Name> = permutator
        .permute(&seeds(&["api.example.com"]))
        .names()
        .filter(|name| filter.check(&mut resolver, name).unwrap() == Verdict::Genuine)
        .collect();
    assert_eq!(live, [real]);
}

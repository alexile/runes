//! Wildcard detection against an in-memory mock zone with RFC 4592
//! wildcard semantics. No network.

// Test helpers outside `#[test]` functions may unwrap too.
#![allow(clippy::unwrap_used, reason = "test code")]

use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use rune_dns_wire::{Name, RData, Rcode, Record, RecordType};
use rune_wildcard_dns::{
    AsyncResolver, Error, Fingerprint, Level, Options, Resolver, Response, Verdict, WildcardFilter,
};

fn name(text: &str) -> Name {
    text.parse().unwrap()
}

const fn v4(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
}

/// What a wildcard answers.
#[derive(Clone)]
enum Wild {
    /// The same addresses every time.
    Static(Vec<IpAddr>),
    /// `per_answer` addresses from `pool`, round robin across queries.
    Rotating {
        pool: Vec<IpAddr>,
        per_answer: usize,
    },
    /// A CNAME to `target`, whose address rotates through `pool`.
    Cname { target: Name, pool: Vec<IpAddr> },
}

#[derive(Default)]
struct Zone {
    apex: Option<Name>,
    hosts: HashMap<Name, Vec<RData>>,
    wildcards: HashMap<Name, Wild>,
    counter: usize,
    queries: Vec<Name>,
    servfail: bool,
    fail_transport: bool,
}

#[derive(Debug, thiserror::Error)]
#[error("transport down")]
struct Down;

impl Zone {
    fn new(apex: &str) -> Self {
        Self {
            apex: Some(name(apex)),
            ..Self::default()
        }
    }

    fn host(mut self, owner: &str, data: RData) -> Self {
        self.hosts
            .entry(name(owner).to_ascii_lowercase())
            .or_default()
            .push(data);
        self
    }

    fn wildcard(mut self, parent: &str, wild: Wild) -> Self {
        self.wildcards
            .insert(name(parent).to_ascii_lowercase(), wild);
        self
    }

    /// Whether `node` exists in the tree: it owns data or has a descendant
    /// that does (an empty non-terminal), or it is the apex.
    fn exists(&self, node: &Name) -> bool {
        self.apex.as_ref() == Some(node) || self.hosts.keys().any(|h| h.is_subdomain_of(node))
    }

    fn records_for(&mut self, owner: &Name, data: Vec<RData>, rtype: RecordType) -> Vec<Record> {
        let mut out = Vec::new();
        for d in data {
            match &d {
                RData::Cname(target) => {
                    out.push(Record::new(owner.clone(), 60, d.clone()));
                    let target = target.clone();
                    let chained = self.lookup(&target, rtype);
                    out.extend(chained.answers);
                }
                RData::A(_) if rtype == RecordType::A => {
                    out.push(Record::new(owner.clone(), 60, d.clone()));
                }
                RData::Aaaa(_) if rtype == RecordType::AAAA => {
                    out.push(Record::new(owner.clone(), 60, d.clone()));
                }
                _ => {}
            }
        }
        out
    }

    fn wild_data(&mut self, wild: Wild) -> Vec<RData> {
        let to_rdata = |ip: IpAddr| match ip {
            IpAddr::V4(a) => RData::A(a),
            IpAddr::V6(a) => RData::Aaaa(a),
        };
        match wild {
            Wild::Static(addrs) => addrs.into_iter().map(to_rdata).collect(),
            Wild::Rotating { pool, per_answer } => {
                let start = self.counter;
                self.counter += per_answer;
                (0..per_answer)
                    .map(|i| to_rdata(pool[(start + i) % pool.len()]))
                    .collect()
            }
            Wild::Cname { target, pool } => {
                // Make the target answer from the rotating pool.
                let ip = pool[self.counter % pool.len()];
                self.counter += 1;
                self.hosts.insert(target.clone(), vec![to_rdata(ip)]);
                vec![RData::Cname(target)]
            }
        }
    }

    fn lookup(&mut self, qname: &Name, rtype: RecordType) -> Response {
        let qname = qname.to_ascii_lowercase();
        if let Some(data) = self.hosts.get(&qname).cloned() {
            return Response::answer(self.records_for(&qname, data, rtype));
        }
        if self.exists(&qname) {
            return Response::answer(vec![]); // empty non-terminal: NODATA
        }
        // Closest encloser, then the wildcard at it, if any.
        let mut encloser = qname.parent();
        while let Some(node) = encloser {
            if self.exists(&node) || node.is_root() {
                if let Some(wild) = self.wildcards.get(&node).cloned() {
                    let data = self.wild_data(wild);
                    return Response::answer(self.records_for(&qname, data, rtype));
                }
                break;
            }
            encloser = node.parent();
        }
        Response::nxdomain()
    }
}

impl Resolver for Zone {
    type Error = Down;

    fn resolve(&mut self, qname: &Name, rtype: RecordType) -> Result<Response, Down> {
        if self.fail_transport {
            return Err(Down);
        }
        self.queries.push(qname.clone());
        if self.servfail {
            return Ok(Response::new(Rcode::SERVFAIL, vec![]));
        }
        Ok(self.lookup(qname, rtype))
    }
}

fn filter() -> WildcardFilter {
    WildcardFilter::new(Options::default().with_seed(0x5eed))
}

#[test]
fn zone_without_wildcard() {
    let mut zone = Zone::new("example.com")
        .host("www.example.com", RData::A(Ipv4Addr::new(192, 0, 2, 80)))
        .host(
            "deep.dev.example.com",
            RData::A(Ipv4Addr::new(192, 0, 2, 81)),
        );
    let mut filter = filter();

    let report = filter.detect(&mut zone, "example.com").unwrap();
    assert!(!report.is_wildcard());
    assert_eq!(report.levels.len(), 2);
    assert_eq!(report.fingerprint(), None);

    assert_eq!(
        filter.check(&mut zone, &name("www.example.com")).unwrap(),
        Verdict::Genuine
    );
    assert_eq!(
        filter.check(&mut zone, &name("nope.example.com")).unwrap(),
        Verdict::Unresolved
    );
    assert_eq!(
        filter
            .check(&mut zone, &name("deep.dev.example.com"))
            .unwrap(),
        Verdict::Genuine
    );
}

#[test]
fn static_wildcard_is_filtered() {
    let mut zone = Zone::new("example.com")
        .host("www.example.com", RData::A(Ipv4Addr::new(192, 0, 2, 80)))
        .host("shared.example.com", RData::A(Ipv4Addr::new(192, 0, 2, 1)))
        .wildcard(
            "example.com",
            Wild::Static(vec![v4(1), IpAddr::V6(Ipv6Addr::LOCALHOST)]),
        );
    let mut filter = filter();

    let report = filter.detect(&mut zone, "example.com").unwrap();
    assert!(report.is_wildcard());
    let fp = report.fingerprint().unwrap();
    assert_eq!(fp.addresses().count(), 2);
    // `*.example.com` also answers two levels down.
    assert!(report.levels[1].level.is_wildcard());

    for guess in ["admin", "vpn", "x1"] {
        let candidate = name(&format!("{guess}.example.com"));
        assert_eq!(
            filter.check(&mut zone, &candidate).unwrap(),
            Verdict::Wildcard
        );
    }
    assert_eq!(
        filter.check(&mut zone, &name("www.example.com")).unwrap(),
        Verdict::Genuine
    );
    // Documented limit: a real host that answers like the wildcard.
    assert_eq!(
        filter
            .check(&mut zone, &name("shared.example.com"))
            .unwrap(),
        Verdict::Wildcard
    );
}

#[test]
fn rotating_wildcard_is_learned_and_filtered() {
    let pool: Vec<IpAddr> = (1..=8).map(v4).collect();
    let mut zone = Zone::new("example.com")
        .host("www.example.com", RData::A(Ipv4Addr::new(198, 51, 100, 7)))
        .wildcard(
            "example.com",
            Wild::Rotating {
                pool: pool.clone(),
                per_answer: 2,
            },
        );
    let mut filter = WildcardFilter::new(
        Options::default()
            .with_seed(9)
            .with_record_types([RecordType::A]),
    );

    let level = filter.learn(&mut zone, &name("example.com")).unwrap();
    // Probing went on past the initial three until rotation repeated.
    assert_eq!(level.fingerprint().unwrap().addresses().count(), pool.len());

    for i in 0..50 {
        let candidate = name(&format!("guess{i}.example.com"));
        assert_eq!(
            filter.check(&mut zone, &candidate).unwrap(),
            Verdict::Wildcard,
            "{candidate}"
        );
    }
    assert_eq!(
        filter.check(&mut zone, &name("www.example.com")).unwrap(),
        Verdict::Genuine
    );
}

#[test]
fn partial_overlap_triggers_more_probes() {
    let pool: Vec<IpAddr> = (1..=6).map(v4).collect();
    let mut zone = Zone::new("example.com").wildcard(
        "example.com",
        Wild::Rotating {
            pool,
            per_answer: 1,
        },
    );
    // Too few probes to learn the pool, and no adaptive growth.
    let mut filter = WildcardFilter::new(
        Options::default()
            .with_seed(3)
            .with_probes(1)
            .with_max_probes(1)
            .with_record_types([RecordType::A]),
    );
    filter.learn(&mut zone, &name("example.com")).unwrap();
    // The seeded fingerprint knows .1 only; a candidate answering .1 and .4
    // partly overlaps, and with no budget left it is judged genuine.
    let response = Response::answer(vec![
        Record::new(
            name("x.example.com"),
            60,
            RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        ),
        Record::new(
            name("x.example.com"),
            60,
            RData::A(Ipv4Addr::new(192, 0, 2, 4)),
        ),
    ]);
    let x = name("x.example.com");
    assert_eq!(
        filter.classify(&mut zone, &x, &response).unwrap(),
        Verdict::Genuine
    );

    // With budget, the filter probes on until .4 shows up.
    let mut filter = WildcardFilter::new(
        Options::default()
            .with_seed(3)
            .with_probes(1)
            .with_max_probes(10)
            .with_record_types([RecordType::A]),
    );
    filter.insert_level(
        &name("example.com"),
        Level::Wildcard(Fingerprint::from_parts([v4(1)], [])),
    );
    assert_eq!(
        filter.classify(&mut zone, &x, &response).unwrap(),
        Verdict::Wildcard
    );
    let learned = filter.level(&name("example.com")).unwrap();
    assert!(
        learned
            .fingerprint()
            .unwrap()
            .addresses()
            .any(|a| *a == v4(4))
    );
}

#[test]
fn cname_wildcard_matches_by_target() {
    let mut zone = Zone::new("example.com")
        .host("app.example.com", RData::Cname(name("app.provider.test")))
        .host("app.provider.test", RData::A(Ipv4Addr::new(203, 0, 113, 9)))
        .wildcard(
            "example.com",
            Wild::Cname {
                target: name("edge.cdn.test"),
                pool: (1..=50).map(v4).collect(),
            },
        );
    let mut filter = filter();
    let report = filter.detect(&mut zone, "example.com").unwrap();
    let fp = report.fingerprint().unwrap();
    assert_eq!(
        fp.cname_targets().collect::<Vec<_>>(),
        [&name("edge.cdn.test")]
    );

    // The CDN hands out a fresh address each time; the target still matches.
    for guess in ["a", "b", "c", "d"] {
        let candidate = name(&format!("{guess}.example.com"));
        assert_eq!(
            filter.check(&mut zone, &candidate).unwrap(),
            Verdict::Wildcard
        );
    }
    assert_eq!(
        filter.check(&mut zone, &name("app.example.com")).unwrap(),
        Verdict::Genuine
    );
}

#[test]
fn wildcard_below_a_clean_apex() {
    let mut zone = Zone::new("example.com")
        .host("www.example.com", RData::A(Ipv4Addr::new(192, 0, 2, 80)))
        .host(
            "api.dev.example.com",
            RData::A(Ipv4Addr::new(192, 0, 2, 90)),
        )
        .wildcard("dev.example.com", Wild::Static(vec![v4(66)]));
    let mut filter = filter();

    assert!(
        !filter
            .detect(&mut zone, "example.com")
            .unwrap()
            .is_wildcard()
    );
    assert_eq!(
        filter.check(&mut zone, &name("x.dev.example.com")).unwrap(),
        Verdict::Wildcard
    );
    assert_eq!(
        filter
            .check(&mut zone, &name("api.dev.example.com"))
            .unwrap(),
        Verdict::Genuine
    );
    assert_eq!(
        filter.check(&mut zone, &name("x.example.com")).unwrap(),
        Verdict::Unresolved
    );
    assert!(
        filter
            .level(&name("dev.example.com"))
            .unwrap()
            .is_wildcard()
    );
    assert_eq!(filter.level(&name("example.com")), Some(Level::Clean));
}

#[test]
fn apex_wildcard_answers_deep_names_but_not_under_existing_nodes() {
    let mut zone = Zone::new("example.com")
        .host(
            "www.corp.example.com",
            RData::A(Ipv4Addr::new(192, 0, 2, 80)),
        )
        .wildcard("example.com", Wild::Static(vec![v4(1)]));
    let mut filter = filter();

    // `b.example.com` does not exist, so `*.example.com` answers `a.b.…`.
    assert_eq!(
        filter.check(&mut zone, &name("a.b.example.com")).unwrap(),
        Verdict::Wildcard
    );
    assert!(filter.level(&name("b.example.com")).unwrap().is_wildcard());
    // `corp.example.com` exists (empty non-terminal): no synthesis below it.
    assert_eq!(
        filter
            .check(&mut zone, &name("x.corp.example.com"))
            .unwrap(),
        Verdict::Unresolved
    );
    assert_eq!(
        filter
            .check(&mut zone, &name("www.corp.example.com"))
            .unwrap(),
        Verdict::Genuine
    );
    assert_eq!(filter.level(&name("corp.example.com")), Some(Level::Clean));
}

#[test]
fn levels_are_probed_once() {
    let mut zone = Zone::new("example.com").wildcard("example.com", Wild::Static(vec![v4(1)]));
    let mut filter = WildcardFilter::new(
        Options::default()
            .with_seed(1)
            .with_record_types([RecordType::A]),
    );
    filter.check(&mut zone, &name("a.example.com")).unwrap();
    let after_first = zone.queries.len();
    // One candidate query plus the initial three probes; a static wildcard
    // stops growing after the first.
    assert_eq!(after_first, 1 + 3);
    filter.check(&mut zone, &name("b.example.com")).unwrap();
    assert_eq!(zone.queries.len(), after_first + 1);

    // Cache-only predicate.
    let response = Response::answer(vec![Record::new(
        name("c.example.com"),
        60,
        RData::A(Ipv4Addr::new(192, 0, 2, 1)),
    )]);
    assert_eq!(
        filter.cached_verdict(&name("c.example.com"), &response),
        Some(Verdict::Wildcard)
    );
    assert_eq!(
        filter.cached_verdict(&name("c.other.test"), &response),
        None
    );
    assert_eq!(
        filter.cached_verdict(&name("c.example.com"), &Response::nxdomain()),
        Some(Verdict::Unresolved)
    );
}

#[test]
fn probes_use_random_labels() {
    let mut zone = Zone::new("example.com");
    let mut filter = filter();
    filter.learn(&mut zone, &name("example.com")).unwrap();
    let mut probes = zone.queries.clone();
    probes.sort();
    probes.dedup();
    assert_eq!(probes.len(), 3, "each probe a fresh label, A and AAAA each");
    assert_eq!(zone.queries.len(), 6);
}

#[test]
fn public_suffix_is_never_probed() {
    let mut zone = Zone::new("co.uk").host("example.co.uk", RData::A(Ipv4Addr::new(192, 0, 2, 1)));
    let mut filter = filter();
    assert_eq!(
        filter.check(&mut zone, &name("example.co.uk")).unwrap(),
        Verdict::Genuine
    );
    assert_eq!(zone.queries.len(), 2, "only the candidate itself");
}

#[test]
fn server_failures_are_inconclusive() {
    let mut zone = Zone::new("example.com");
    zone.servfail = true;
    let mut filter = filter();
    let err = filter.learn(&mut zone, &name("example.com")).unwrap_err();
    assert!(matches!(err, Error::Inconclusive { .. }), "{err}");
    assert_eq!(
        filter.level(&name("example.com")),
        None,
        "failures are not cached"
    );
}

#[test]
fn transport_errors_propagate() {
    let mut zone = Zone::new("example.com");
    zone.fail_transport = true;
    let err = filter().detect(&mut zone, "example.com").unwrap_err();
    assert!(matches!(err, Error::Resolver { .. }));
    assert!(err.to_string().contains("transport down"));
}

#[test]
fn unicode_domains_are_normalized() {
    let mut zone = Zone::new("xn--bcher-kva.example")
        .wildcard("xn--bcher-kva.example", Wild::Static(vec![v4(1)]));
    let report = filter().detect(&mut zone, "Bücher.example").unwrap();
    assert_eq!(report.domain, name("xn--bcher-kva.example"));
    assert!(report.is_wildcard());
}

#[test]
fn closure_resolver() {
    let mut resolver = rune_wildcard_dns::from_fn(|_: &Name, _: RecordType| {
        Ok::<_, Infallible>(Response::nxdomain())
    });
    let report = filter().detect(&mut resolver, "example.org").unwrap();
    assert!(!report.is_wildcard());
}

/// An async resolver whose every lookup is pending once before completing.
struct Yielding(Zone);

impl AsyncResolver for Yielding {
    type Error = Down;

    fn resolve(
        &mut self,
        qname: &Name,
        rtype: RecordType,
    ) -> impl Future<Output = Result<Response, Down>> + Send {
        let result = Resolver::resolve(&mut self.0, qname, rtype);
        let mut yielded = false;
        let mut result = Some(result);
        std::future::poll_fn(move |cx| {
            if yielded {
                Poll::Ready(result.take().unwrap())
            } else {
                yielded = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        })
    }
}

fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(out) = future.as_mut().poll(&mut cx) {
            return out;
        }
    }
}

#[test]
fn async_resolver() {
    let zone = Zone::new("example.com")
        .host("www.example.com", RData::A(Ipv4Addr::new(192, 0, 2, 80)))
        .wildcard("example.com", Wild::Static(vec![v4(1)]));
    let mut resolver = Yielding(zone);
    let mut filter = filter();
    let verdicts = block_on(async {
        let report = filter
            .detect_async(&mut resolver, "example.com")
            .await
            .unwrap();
        assert!(report.is_wildcard());
        let a = filter
            .check_async(&mut resolver, &name("www.example.com"))
            .await
            .unwrap();
        let b = filter
            .check_async(&mut resolver, &name("zz.example.com"))
            .await
            .unwrap();
        (a, b)
    });
    assert_eq!(verdicts, (Verdict::Genuine, Verdict::Wildcard));
}

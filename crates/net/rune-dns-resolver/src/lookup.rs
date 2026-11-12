//! Sans-I/O query building, response checks and answer reading.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rune_dns_wire::{
    Caa, Edns, Message, Mx, Name, Question, RData, Rcode, Record, RecordType, Soa, Srv,
};

use crate::{Error, ResolverOptions};

/// A query for `question` with id `id`, flags and EDNS(0) from `options`.
///
/// Use a random id for UDP, TCP and TLS (it is the main defence against
/// off-path spoofing); RFC 8484 §4.1 asks for id 0 over HTTPS, where the
/// id is not needed and 0 keeps answers cacheable.
#[must_use]
pub fn build_query(id: u16, question: Question, options: &ResolverOptions) -> Message {
    let query = Message::query(id, question).with_recursion_desired(options.recursion_desired);
    match options.udp_payload_size {
        Some(size) => query.with_edns(
            Edns::default()
                .with_udp_payload_size(size.max(512))
                .with_dnssec_ok(options.dnssec_ok),
        ),
        None => query,
    }
}

/// Checks that `response` answers `query`: the `QR` bit, the id, the
/// opcode and the question (compared ignoring ASCII case, so answers to
/// 0x20-randomised names match).
///
/// Some servers drop the question from error responses (`FORMERR`,
/// `REFUSED`, ...); those are accepted without one.
///
/// # Errors
///
/// [`Error::Mismatch`] naming the first field that differs.
pub fn check_response(query: &Message, response: &Message) -> Result<(), Error> {
    let mismatch = |reason| Err(Error::Mismatch { reason });
    if !response.header.response {
        return mismatch("not a response");
    }
    if response.header.id != query.header.id {
        return mismatch("id");
    }
    if response.header.opcode != query.header.opcode {
        return mismatch("opcode");
    }
    let same = |a: &Question, b: &Question| {
        a.qtype == b.qtype && a.qclass == b.qclass && a.name.eq_ignore_ascii_case(&b.name)
    };
    match (query.questions.as_slice(), response.questions.as_slice()) {
        ([asked], [answered]) if same(asked, answered) => Ok(()),
        (_, []) if response.header.rcode != Rcode::NOERROR => Ok(()),
        _ => mismatch("question"),
    }
}

/// The reverse-lookup name of an address: `4.3.2.1.in-addr.arpa` for
/// `1.2.3.4`, nibbles under `ip6.arpa` for IPv6 (RFC 1035 §3.5,
/// RFC 3596 §2.5).
///
/// ```
/// use rune_dns_resolver::reverse_name;
///
/// assert_eq!(reverse_name("192.0.2.1".parse()?).to_string(), "1.2.0.192.in-addr.arpa");
/// assert!(reverse_name("2001:db8::1".parse()?).to_string()
///     .starts_with("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[must_use]
pub fn reverse_name(ip: IpAddr) -> Name {
    let labels: Vec<String> = match ip {
        IpAddr::V4(v4) => v4
            .octets()
            .iter()
            .rev()
            .map(ToString::to_string)
            .chain(["in-addr".to_owned(), "arpa".to_owned()])
            .collect(),
        IpAddr::V6(v6) => v6
            .octets()
            .iter()
            .rev()
            .flat_map(|byte| [byte & 0xF, byte >> 4])
            .map(|nibble| format!("{nibble:x}"))
            .chain(["ip6".to_owned(), "arpa".to_owned()])
            .collect(),
    };
    // At most 34 short labels: always a valid name.
    Name::from_labels(labels).unwrap_or_else(|_| Name::root())
}

/// A question and the response that answered it.
///
/// [`Lookup::records`] picks the answer records for the question, following
/// `CNAME`s from the question name through the answer section (at most 8
/// links by default). The typed accessors read their data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lookup {
    /// The question asked.
    pub question: Question,
    /// The response, as received.
    pub response: Message,
    max_cname_chain: usize,
}

impl Lookup {
    /// A lookup of `question` answered by `response`.
    #[must_use]
    pub const fn new(question: Question, response: Message) -> Self {
        Self {
            question,
            response,
            max_cname_chain: 8,
        }
    }

    /// Sets how many `CNAME` links [`Lookup::records`] follows.
    #[must_use]
    pub const fn with_max_cname_chain(mut self, max: usize) -> Self {
        self.max_cname_chain = max;
        self
    }

    /// The response code.
    #[must_use]
    pub const fn rcode(&self) -> Rcode {
        self.response.header.rcode
    }

    /// Whether the name does not exist.
    #[must_use]
    pub fn is_nxdomain(&self) -> bool {
        self.rcode() == Rcode::NXDOMAIN
    }

    /// The answer records of the question's type, at the question name or
    /// at the end of its `CNAME` chain. For a `CNAME` or `ANY` question,
    /// the records at the question name itself.
    #[must_use]
    pub fn records(&self) -> Vec<&Record> {
        self.chase().0
    }

    /// The names the question name was aliased to, in order.
    #[must_use]
    pub fn cname_chain(&self) -> Vec<Name> {
        self.chase().1
    }

    /// The smallest TTL among [`Lookup::records`].
    #[must_use]
    pub fn min_ttl(&self) -> Option<u32> {
        self.records().iter().map(|record| record.ttl).min()
    }

    fn chase(&self) -> (Vec<&Record>, Vec<Name>) {
        let qtype = self.question.qtype;
        let answers = &self.response.answers;
        let mut target = self.question.name.clone();
        let mut chain = Vec::new();
        loop {
            let at_target = |record: &&Record| record.name.eq_ignore_ascii_case(&target);
            let found: Vec<&Record> = answers
                .iter()
                .filter(at_target)
                .filter(|record| qtype == RecordType::ANY || record.rtype() == qtype)
                .collect();
            if !found.is_empty() || qtype == RecordType::CNAME || qtype == RecordType::ANY {
                return (found, chain);
            }
            let next = answers
                .iter()
                .filter(at_target)
                .find_map(|record| match &record.data {
                    RData::Cname(alias) => Some(alias.clone()),
                    _ => None,
                });
            match next {
                Some(alias) if chain.len() < self.max_cname_chain && !chain.contains(&alias) => {
                    chain.push(alias.clone());
                    target = alias;
                }
                _ => return (Vec::new(), chain),
            }
        }
    }

    fn data(&self) -> impl Iterator<Item = &RData> {
        self.records().into_iter().map(|record| &record.data)
    }

    /// `A` addresses.
    #[must_use]
    pub fn ipv4(&self) -> Vec<Ipv4Addr> {
        self.data()
            .filter_map(|data| match data {
                RData::A(addr) => Some(*addr),
                _ => None,
            })
            .collect()
    }

    /// `AAAA` addresses.
    #[must_use]
    pub fn ipv6(&self) -> Vec<Ipv6Addr> {
        self.data()
            .filter_map(|data| match data {
                RData::Aaaa(addr) => Some(*addr),
                _ => None,
            })
            .collect()
    }

    /// Names from `NS`, `CNAME` or `PTR` records.
    #[must_use]
    pub fn names(&self) -> Vec<Name> {
        self.data()
            .filter_map(|data| match data {
                RData::Ns(name) | RData::Cname(name) | RData::Ptr(name) => Some(name.clone()),
                _ => None,
            })
            .collect()
    }

    /// `MX` records, sorted by preference.
    #[must_use]
    pub fn mx(&self) -> Vec<Mx> {
        let mut records: Vec<Mx> = self
            .data()
            .filter_map(|data| match data {
                RData::Mx(mx) => Some(mx.clone()),
                _ => None,
            })
            .collect();
        records.sort_by_key(|mx| mx.preference);
        records
    }

    /// `TXT` records, each with its strings joined (as SPF, DKIM and DMARC
    /// read them).
    #[must_use]
    pub fn txt(&self) -> Vec<Vec<u8>> {
        self.data()
            .filter_map(|data| match data {
                RData::Txt(strings) => Some(strings.concat()),
                _ => None,
            })
            .collect()
    }

    /// The first `SOA` record in the answer.
    #[must_use]
    pub fn soa(&self) -> Option<Soa> {
        self.data().find_map(|data| match data {
            RData::Soa(soa) => Some(soa.clone()),
            _ => None,
        })
    }

    /// `SRV` records, sorted by priority, then by descending weight.
    #[must_use]
    pub fn srv(&self) -> Vec<Srv> {
        let mut records: Vec<Srv> = self
            .data()
            .filter_map(|data| match data {
                RData::Srv(srv) => Some(srv.clone()),
                _ => None,
            })
            .collect();
        records.sort_by_key(|srv| (srv.priority, core::cmp::Reverse(srv.weight)));
        records
    }

    /// `CAA` records.
    #[must_use]
    pub fn caa(&self) -> Vec<Caa> {
        self.data()
            .filter_map(|data| match data {
                RData::Caa(caa) => Some(caa.clone()),
                _ => None,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(text: &str) -> Name {
        Name::from_ascii(text).unwrap()
    }

    fn query() -> Message {
        build_query(
            7,
            Question::new(name("www.example.com"), RecordType::A),
            &ResolverOptions::default(),
        )
    }

    #[test]
    fn query_flags() {
        let query = query();
        assert!(query.header.recursion_desired);
        assert_eq!(query.edns.as_ref().map(|e| e.udp_payload_size), Some(1232));
        let plain = build_query(
            1,
            Question::new(Name::root(), RecordType::NS),
            &ResolverOptions::default()
                .with_udp_payload_size(None)
                .with_recursion_desired(false),
        );
        assert!(plain.edns.is_none());
        assert!(!plain.header.recursion_desired);
        let dnssec = build_query(
            1,
            Question::new(Name::root(), RecordType::NS),
            &ResolverOptions::default()
                .with_dnssec_ok(true)
                .with_udp_payload_size(Some(100)),
        );
        let edns = dnssec.edns.unwrap();
        assert!(edns.dnssec_ok());
        assert_eq!(edns.udp_payload_size, 512);
    }

    #[test]
    fn response_checks() {
        let query = query();
        let good = Message::response_to(&query);
        assert!(check_response(&query, &good).is_ok());

        let mut upper = good.clone();
        upper.questions[0].name = name("WWW.Example.COM");
        assert!(check_response(&query, &upper).is_ok());

        let reason = |response: &Message| match check_response(&query, response) {
            Err(Error::Mismatch { reason }) => reason,
            other => panic!("{other:?}"),
        };
        assert_eq!(reason(&query), "not a response");
        assert_eq!(reason(&good.clone().with_id(8)), "id");
        let mut other = good.clone();
        other.questions[0].qtype = RecordType::AAAA;
        assert_eq!(reason(&other), "question");
        let mut empty = good.clone();
        empty.questions.clear();
        assert_eq!(reason(&empty), "question");
        assert!(check_response(&query, &empty.with_rcode(Rcode::REFUSED)).is_ok());
        let mut opcode = good;
        opcode.header.opcode = rune_dns_wire::Opcode::STATUS;
        assert_eq!(reason(&opcode), "opcode");
    }

    #[test]
    fn reverse_names() {
        assert_eq!(
            reverse_name(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))).to_string(),
            "3.2.1.10.in-addr.arpa"
        );
        let v6 = reverse_name("2001:db8::567:89ab".parse().unwrap()).to_string();
        assert_eq!(
            v6,
            "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        );
    }

    fn lookup(qtype: RecordType, answers: Vec<Record>) -> Lookup {
        let question = Question::new(name("a.example"), qtype);
        let response = answers.into_iter().fold(
            Message::response_to(&Message::query(1, question.clone())),
            Message::with_answer,
        );
        Lookup::new(question, response)
    }

    fn cname(from: &str, to: &str) -> Record {
        Record::new(name(from), 60, RData::Cname(name(to)))
    }

    fn a(owner: &str, last: u8, ttl: u32) -> Record {
        Record::new(name(owner), ttl, RData::A(Ipv4Addr::new(192, 0, 2, last)))
    }

    #[test]
    fn follows_cname_chains() {
        let chained = lookup(
            RecordType::A,
            vec![
                cname("A.example", "b.example"),
                cname("b.example", "c.example"),
                a("c.example", 1, 30),
                a("c.example", 2, 20),
                a("unrelated.example", 3, 1),
            ],
        );
        assert_eq!(
            chained.ipv4(),
            [Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(192, 0, 2, 2)]
        );
        assert_eq!(
            chained.cname_chain(),
            [name("b.example"), name("c.example")]
        );
        assert_eq!(chained.min_ttl(), Some(20));

        let looped = lookup(
            RecordType::A,
            vec![
                cname("a.example", "b.example"),
                cname("b.example", "a.example"),
            ],
        );
        assert_eq!(looped.records().len(), 0);

        let long: Vec<Record> = (0..12)
            .map(|i| {
                cname(
                    &format!(
                        "{}.example",
                        if i == 0 {
                            "a".to_owned()
                        } else {
                            format!("n{i}")
                        }
                    ),
                    &format!("n{}.example", i + 1),
                )
            })
            .chain([a("n12.example", 9, 1)])
            .collect();
        let limited = lookup(RecordType::A, long);
        assert_eq!(limited.records().len(), 0);
        assert_eq!(limited.cname_chain().len(), 8);
        assert_eq!(limited.with_max_cname_chain(12).ipv4().len(), 1);

        let direct = lookup(RecordType::CNAME, vec![cname("a.example", "b.example")]);
        assert_eq!(direct.names(), [name("b.example")]);
        assert_eq!(direct.cname_chain().len(), 0);
    }

    #[test]
    fn typed_accessors_sort() {
        let mx = |preference, host: &str| {
            Record::new(
                name("a.example"),
                1,
                RData::Mx(Mx {
                    preference,
                    exchange: name(host),
                }),
            )
        };
        let lookup_mx = lookup(RecordType::MX, vec![mx(20, "b"), mx(10, "a")]);
        let order: Vec<u16> = lookup_mx.mx().iter().map(|m| m.preference).collect();
        assert_eq!(order, [10, 20]);

        let srv = |priority, weight| {
            Record::new(
                name("a.example"),
                1,
                RData::Srv(Srv {
                    priority,
                    weight,
                    port: 1,
                    target: Name::root(),
                }),
            )
        };
        let lookup_srv = lookup(RecordType::SRV, vec![srv(2, 1), srv(1, 5), srv(1, 50)]);
        let order: Vec<(u16, u16)> = lookup_srv
            .srv()
            .iter()
            .map(|s| (s.priority, s.weight))
            .collect();
        assert_eq!(order, [(1, 50), (1, 5), (2, 1)]);

        let txt = lookup(
            RecordType::TXT,
            vec![Record::new(
                name("a.example"),
                1,
                RData::Txt(vec![b"v=spf1 ".to_vec(), b"-all".to_vec()]),
            )],
        );
        assert_eq!(txt.txt(), [b"v=spf1 -all".to_vec()]);
        assert!(!txt.is_nxdomain());
        assert_eq!(txt.soa(), None);
        assert_eq!(txt.caa().len(), 0);
        assert_eq!(txt.ipv6().len(), 0);
    }
}

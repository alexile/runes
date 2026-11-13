//! Zone transfers: AXFR (RFC 5936) and IXFR (RFC 1995) response streams.

use rune_dns_wire::{
    MAX_MESSAGE_LEN, Message, Name, Opcode, Question, RData, Rcode, Record, RecordType, Soa,
};

use crate::Error;
use crate::zone::Zone;

/// Default cap on records accepted from one transfer.
const DEFAULT_MAX_RECORDS: usize = 10_000_000;

/// An AXFR request for `zone` (RFC 5936 §2.2): one question, no recursion.
#[must_use]
pub fn axfr_query(id: u16, zone: Name) -> Message {
    Message::query(id, Question::new(zone, RecordType::AXFR)).with_recursion_desired(false)
}

/// An IXFR request for `zone` (RFC 1995 §3): the client's current `SOA` goes
/// in the authority section, and the server answers with the changes since
/// its serial.
#[must_use]
pub fn ixfr_query(id: u16, zone: Name, current: Soa) -> Message {
    let soa = Record::new(zone.clone(), 0, RData::Soa(current));
    Message::query(id, Question::new(zone, RecordType::IXFR))
        .with_recursion_desired(false)
        .with_authority(soa)
}

/// Whether a transfer needs more messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Status {
    /// Read and push the next message.
    More,
    /// The closing record has arrived; call `finish`.
    Done,
}

/// Checks shared by AXFR and IXFR.
#[derive(Debug, Clone)]
struct Session {
    zone: Name,
    qtype: RecordType,
    id: Option<u16>,
    max_records: usize,
    records: usize,
}

impl Session {
    const fn new(zone: Name, qtype: RecordType) -> Self {
        Self {
            zone,
            qtype,
            id: None,
            max_records: DEFAULT_MAX_RECORDS,
            records: 0,
        }
    }

    fn check(&self, message: &Message, first: bool) -> Result<(), Error> {
        let header = &message.header;
        let fail = |reason| Err(Error::Transfer { reason });
        if !header.response {
            return fail("message is not a response");
        }
        if self.id.is_some_and(|id| id != header.id) {
            return fail("response id does not match the query");
        }
        if header.opcode != Opcode::QUERY {
            return fail("response opcode is not QUERY");
        }
        if header.rcode != Rcode::NOERROR {
            return Err(Error::Rcode(header.rcode));
        }
        if header.truncated {
            return fail("response is truncated; transfer over TCP");
        }
        match message.questions.as_slice() {
            [] => {}
            [question]
                if question.qtype == self.qtype
                    && question.name.eq_ignore_ascii_case(&self.zone) => {}
            _ => return fail("question does not match the transfer"),
        }
        if first && message.answers.is_empty() {
            return fail("first response has no answer records");
        }
        Ok(())
    }

    /// Counts a record against the limit and returns its `SOA` serial, if it
    /// is the zone's `SOA`.
    fn record(&mut self, record: &Record) -> Result<Option<u32>, Error> {
        self.records += 1;
        if self.records > self.max_records {
            return Err(Error::TooManyRecords {
                max: self.max_records,
            });
        }
        match &record.data {
            RData::Soa(soa) if record.name.eq_ignore_ascii_case(&self.zone) => Ok(Some(soa.serial)),
            RData::Soa(_) => Err(Error::Transfer {
                reason: "SOA record of another zone",
            }),
            _ => Ok(None),
        }
    }

    /// Whether `record`'s owner lies outside the zone. Such records are
    /// dropped: a primary has no business sending them, and keeping them
    /// would let it plant names of other zones in the transfer.
    fn outside(&self, record: &Record) -> bool {
        !record.name.is_subdomain_of(&self.zone)
    }
}

/// Reassembles an AXFR response (RFC 5936) from its messages.
///
/// The stream must open with the zone's `SOA` and closes with the same
/// `SOA` again. Records in between whose owner lies outside the zone are
/// dropped (they still count towards [`Axfr::with_max_records`]). Messages are
/// checked for a matching id (with [`Axfr::with_id`]), the response flag,
/// `NOERROR` (other codes become [`Error::Rcode`]), and a matching question
/// when they carry one.
///
/// ```
/// use std::net::Ipv4Addr;
/// use rune_dns_wire::{Message, Name, RData, Record, Soa};
/// use rune_dns_zone::{Axfr, Status, axfr_query};
///
/// let zone: Name = "example.com".parse()?;
/// let query = axfr_query(7, zone.clone());
/// let soa = Record::new(zone.clone(), 3600, RData::Soa(Soa {
///     mname: "ns.example.com".parse()?,
///     rname: "hostmaster.example.com".parse()?,
///     serial: 1, refresh: 7200, retry: 900, expire: 1_209_600, minimum: 300,
/// }));
/// let www = Record::new("www.example.com".parse()?, 300, RData::A(Ipv4Addr::new(192, 0, 2, 1)));
///
/// // The server may split the zone over several messages.
/// let first = Message::response_to(&query).with_answer(soa.clone()).with_answer(www.clone());
/// let last = Message::response_to(&query).with_answer(soa.clone());
///
/// let mut axfr = Axfr::new(zone).with_id(7);
/// assert_eq!(axfr.push_bytes(&first.encode()?)?, Status::More);
/// assert_eq!(axfr.push(&last)?, Status::Done);
/// let zone = axfr.finish()?;
/// assert_eq!(zone.records, [soa, www]);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone)]
pub struct Axfr {
    session: Session,
    serial: Option<u32>,
    records: Vec<Record>,
    done: bool,
}

impl Axfr {
    /// Starts reassembling a transfer of `zone`.
    #[must_use]
    pub const fn new(zone: Name) -> Self {
        Self {
            session: Session::new(zone, RecordType::AXFR),
            serial: None,
            records: Vec::new(),
            done: false,
        }
    }

    /// Requires every message to carry this id, the query's.
    #[must_use]
    pub const fn with_id(mut self, id: u16) -> Self {
        self.session.id = Some(id);
        self
    }

    /// Caps the number of records accepted (default 10 000 000).
    #[must_use]
    pub const fn with_max_records(mut self, max: usize) -> Self {
        self.session.max_records = max;
        self
    }

    /// Decodes and adds one message.
    ///
    /// # Errors
    ///
    /// [`Error::Decode`] for a malformed message, otherwise as
    /// [`Axfr::push`].
    pub fn push_bytes(&mut self, bytes: &[u8]) -> Result<Status, Error> {
        let message = Message::decode(bytes).map_err(Error::Decode)?;
        self.push(&message)
    }

    /// Adds one message of the response.
    ///
    /// # Errors
    ///
    /// [`Error::Rcode`] when the server refused, [`Error::Transfer`] for a
    /// response that breaks RFC 5936, [`Error::TooManyRecords`] past the
    /// cap.
    pub fn push(&mut self, message: &Message) -> Result<Status, Error> {
        if self.done {
            return Err(Error::Transfer {
                reason: "message after the end of the transfer",
            });
        }
        self.session.check(message, self.serial.is_none())?;
        for record in &message.answers {
            if self.done {
                return Err(Error::Transfer {
                    reason: "records after the closing SOA",
                });
            }
            let soa = self.session.record(record)?;
            match (self.serial, soa) {
                (None, Some(serial)) => {
                    self.serial = Some(serial);
                    self.records.push(record.clone());
                }
                (None, None) => {
                    return Err(Error::Transfer {
                        reason: "first record is not the zone's SOA",
                    });
                }
                (Some(opening), Some(closing)) => {
                    if opening != closing {
                        return Err(Error::Transfer {
                            reason: "closing SOA serial differs from the opening one",
                        });
                    }
                    self.done = true;
                }
                (Some(_), None) if self.session.outside(record) => {}
                (Some(_), None) => self.records.push(record.clone()),
            }
        }
        Ok(self.status())
    }

    const fn status(&self) -> Status {
        if self.done {
            Status::Done
        } else {
            Status::More
        }
    }

    /// Whether the closing `SOA` has arrived.
    #[must_use]
    pub const fn is_done(&self) -> bool {
        self.done
    }

    /// The records received so far, opening `SOA` first.
    #[must_use]
    pub fn records(&self) -> &[Record] {
        &self.records
    }

    /// The transferred zone: the opening `SOA` and every record after it,
    /// without the closing `SOA`.
    ///
    /// # Errors
    ///
    /// [`Error::Transfer`] if the closing `SOA` has not arrived.
    pub fn finish(self) -> Result<Zone, Error> {
        if !self.done {
            return Err(Error::Transfer {
                reason: "transfer ended before the closing SOA",
            });
        }
        Ok(Zone::new(self.records))
    }
}

/// One step of an incremental transfer: the changes from serial `from` to
/// serial `to`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IxfrDiff {
    /// The `SOA` of the old version.
    pub from: Record,
    /// The `SOA` of the new version.
    pub to: Record,
    /// Records deleted.
    pub removed: Vec<Record>,
    /// Records added.
    pub added: Vec<Record>,
}

/// The result of an IXFR (RFC 1995 §4).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum IxfrOutcome {
    /// The client's version is current: the server sent only its `SOA`.
    UpToDate(Record),
    /// The server sent the whole zone, AXFR style.
    Full(Zone),
    /// The server sent the differences, oldest first.
    Incremental {
        /// The server's current `SOA`.
        soa: Record,
        /// The difference sequences, chained from the client's serial to
        /// the server's.
        diffs: Vec<IxfrDiff>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Start,
    AfterFirst,
    Full,
    Deleting,
    Adding,
    UpToDate,
    FullDone,
    IncrementalDone,
}

/// Reassembles an IXFR response (RFC 1995) from its messages, telling the
/// three answer forms apart: up to date (one `SOA`), a full zone, or a
/// series of incremental differences.
///
/// Records whose owner lies outside the zone are dropped, as for [`Axfr`].
///
/// ```
/// use std::net::Ipv4Addr;
/// use rune_dns_wire::{Message, Name, RData, Record, Soa};
/// use rune_dns_zone::{Ixfr, IxfrOutcome, Status, ixfr_query};
///
/// let zone: Name = "example.com".parse()?;
/// let soa = |serial| Record::new(zone.clone(), 3600, RData::Soa(Soa {
///     mname: "ns.example.com".parse().unwrap(),
///     rname: "hostmaster.example.com".parse().unwrap(),
///     serial, refresh: 7200, retry: 900, expire: 1_209_600, minimum: 300,
/// }));
/// let a = |last| Record::new("www.example.com".parse().unwrap(), 300,
///     RData::A(Ipv4Addr::new(192, 0, 2, last)));
///
/// let RData::Soa(current) = soa(1).data else { unreachable!() };
/// let query = ixfr_query(9, zone.clone(), current);
/// let response = Message::response_to(&query)
///     .with_answer(soa(2))
///     .with_answer(soa(1)).with_answer(a(1)) // delete www A .1
///     .with_answer(soa(2)).with_answer(a(2)) // add www A .2
///     .with_answer(soa(2));
///
/// let mut ixfr = Ixfr::new(zone, 1).with_id(9);
/// assert_eq!(ixfr.push(&response)?, Status::Done);
/// let IxfrOutcome::Incremental { diffs, .. } = ixfr.finish()? else { unreachable!() };
/// assert_eq!((diffs[0].removed.clone(), diffs[0].added.clone()), (vec![a(1)], vec![a(2)]));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone)]
pub struct Ixfr {
    session: Session,
    client_serial: u32,
    phase: Phase,
    first: Option<Record>,
    full: Vec<Record>,
    diffs: Vec<IxfrDiff>,
    pending: Option<IxfrDiff>,
}

impl Ixfr {
    /// Starts reassembling an incremental transfer of `zone` for a client
    /// at `client_serial`.
    #[must_use]
    pub const fn new(zone: Name, client_serial: u32) -> Self {
        Self {
            session: Session::new(zone, RecordType::IXFR),
            client_serial,
            phase: Phase::Start,
            first: None,
            full: Vec::new(),
            diffs: Vec::new(),
            pending: None,
        }
    }

    /// Requires every message to carry this id, the query's.
    #[must_use]
    pub const fn with_id(mut self, id: u16) -> Self {
        self.session.id = Some(id);
        self
    }

    /// Caps the number of records accepted (default 10 000 000).
    #[must_use]
    pub const fn with_max_records(mut self, max: usize) -> Self {
        self.session.max_records = max;
        self
    }

    /// Decodes and adds one message.
    ///
    /// # Errors
    ///
    /// [`Error::Decode`] for a malformed message, otherwise as
    /// [`Ixfr::push`].
    pub fn push_bytes(&mut self, bytes: &[u8]) -> Result<Status, Error> {
        let message = Message::decode(bytes).map_err(Error::Decode)?;
        self.push(&message)
    }

    /// Adds one message of the response.
    ///
    /// A first message holding only the server's `SOA` means "up to date"
    /// when that serial is not newer than the client's (RFC 1982
    /// arithmetic); otherwise more messages are expected.
    ///
    /// # Errors
    ///
    /// As [`Axfr::push`].
    pub fn push(&mut self, message: &Message) -> Result<Status, Error> {
        if self.is_done() {
            return Err(Error::Transfer {
                reason: "message after the end of the transfer",
            });
        }
        let first_message = self.phase == Phase::Start;
        self.session.check(message, first_message)?;
        for record in &message.answers {
            self.record(record)?;
        }
        if first_message && self.phase == Phase::AfterFirst {
            let serial = self.first.as_ref().and_then(soa_serial).unwrap_or_default();
            if !serial_newer(serial, self.client_serial) {
                self.phase = Phase::UpToDate;
            }
        }
        Ok(if self.is_done() {
            Status::Done
        } else {
            Status::More
        })
    }

    fn record(&mut self, record: &Record) -> Result<(), Error> {
        let soa = self.session.record(record)?;
        let in_body = matches!(
            self.phase,
            Phase::AfterFirst | Phase::Full | Phase::Deleting | Phase::Adding
        );
        if soa.is_none() && in_body && self.session.outside(record) {
            return Ok(());
        }
        let newest = self.first.as_ref().and_then(soa_serial);
        let fail = |reason| Err(Error::Transfer { reason });
        match (self.phase, soa) {
            (Phase::Start, Some(_)) => {
                self.first = Some(record.clone());
                self.phase = Phase::AfterFirst;
            }
            (Phase::Start, None) => return fail("first record is not the zone's SOA"),
            (Phase::AfterFirst, Some(serial)) if Some(serial) == newest => {
                // AXFR-style answer for a zone holding only its SOA.
                self.full.extend(self.first.clone());
                self.phase = Phase::FullDone;
            }
            (Phase::AfterFirst, Some(_)) => {
                self.start_diff(record)?;
            }
            (Phase::AfterFirst, None) => {
                self.full.extend(self.first.clone());
                self.full.push(record.clone());
                self.phase = Phase::Full;
            }
            (Phase::Full, Some(serial)) => {
                if Some(serial) != newest {
                    return fail("closing SOA serial differs from the opening one");
                }
                self.phase = Phase::FullDone;
            }
            (Phase::Full, None) => self.full.push(record.clone()),
            (Phase::Deleting, Some(_)) => {
                if let Some(pending) = &mut self.pending {
                    pending.to = record.clone();
                }
                self.phase = Phase::Adding;
            }
            (Phase::Deleting, None) => {
                if let Some(pending) = &mut self.pending {
                    pending.removed.push(record.clone());
                }
            }
            (Phase::Adding, Some(serial)) => {
                self.diffs.extend(self.pending.take());
                if Some(serial) == newest {
                    self.phase = Phase::IncrementalDone;
                } else {
                    self.start_diff(record)?;
                }
            }
            (Phase::Adding, None) => {
                if let Some(pending) = &mut self.pending {
                    pending.added.push(record.clone());
                }
            }
            (Phase::UpToDate | Phase::FullDone | Phase::IncrementalDone, _) => {
                return fail("records after the closing SOA");
            }
        }
        Ok(())
    }

    /// Opens a difference sequence at the old-version `SOA` `from`, which
    /// must continue where the previous one ended.
    fn start_diff(&mut self, from: &Record) -> Result<(), Error> {
        if self
            .diffs
            .last()
            .is_some_and(|previous| soa_serial(&previous.to) != soa_serial(from))
        {
            return Err(Error::Transfer {
                reason: "IXFR difference sequences do not chain",
            });
        }
        self.pending = Some(IxfrDiff {
            from: from.clone(),
            to: from.clone(),
            removed: Vec::new(),
            added: Vec::new(),
        });
        self.phase = Phase::Deleting;
        Ok(())
    }

    /// Whether the transfer is complete.
    #[must_use]
    pub const fn is_done(&self) -> bool {
        matches!(
            self.phase,
            Phase::UpToDate | Phase::FullDone | Phase::IncrementalDone
        )
    }

    /// The outcome of the transfer.
    ///
    /// # Errors
    ///
    /// [`Error::Transfer`] if the transfer is not complete.
    pub fn finish(self) -> Result<IxfrOutcome, Error> {
        let incomplete = Error::Transfer {
            reason: "transfer ended before the closing SOA",
        };
        let first = self.first.ok_or_else(|| incomplete.clone())?;
        match self.phase {
            Phase::UpToDate => Ok(IxfrOutcome::UpToDate(first)),
            Phase::FullDone => Ok(IxfrOutcome::Full(Zone::new(self.full))),
            Phase::IncrementalDone => Ok(IxfrOutcome::Incremental {
                soa: first,
                diffs: self.diffs,
            }),
            _ => Err(incomplete),
        }
    }
}

const fn soa_serial(record: &Record) -> Option<u32> {
    match &record.data {
        RData::Soa(soa) => Some(soa.serial),
        _ => None,
    }
}

/// `a > b` in RFC 1982 serial-number arithmetic.
const fn serial_newer(a: u32, b: u32) -> bool {
    a != b && a.wrapping_sub(b) < (1 << 31)
}

/// Splits a DNS-over-TCP byte stream (RFC 1035 §4.2.2: each message behind
/// a two-octet length) into messages.
///
/// ```
/// use rune_dns_zone::TcpFrames;
///
/// let mut frames = TcpFrames::new();
/// frames.push(&[0, 3, b'a', b'b']);
/// assert_eq!(frames.next_frame(), None);
/// frames.push(&[b'c', 0, 1]);
/// assert_eq!(frames.next_frame().as_deref(), Some(&b"abc"[..]));
/// assert_eq!(frames.next_frame(), None);
/// assert_eq!(frames.buffered(), 2);
/// assert_eq!(TcpFrames::frame(b"xy")?, [0, 2, b'x', b'y']);
/// # Ok::<(), rune_dns_zone::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TcpFrames {
    buffer: Vec<u8>,
}

impl TcpFrames {
    /// An empty buffer.
    #[must_use]
    pub const fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    /// Appends bytes read from the stream.
    pub fn push(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    /// The next complete message, if one is buffered.
    pub fn next_frame(&mut self) -> Option<Vec<u8>> {
        let len = match self.buffer.get(..2)? {
            &[high, low] => usize::from(u16::from_be_bytes([high, low])),
            _ => return None,
        };
        let frame = self.buffer.get(2..2 + len)?.to_vec();
        self.buffer.drain(..2 + len);
        Some(frame)
    }

    /// Bytes buffered but not yet returned as a frame.
    #[must_use]
    pub const fn buffered(&self) -> usize {
        self.buffer.len()
    }

    /// Prefixes `message` with its length, for sending over TCP.
    ///
    /// # Errors
    ///
    /// [`Error::Decode`] wrapping
    /// [`MessageTooLong`](rune_dns_wire::Error::MessageTooLong) past 65 535
    /// octets.
    pub fn frame(message: &[u8]) -> Result<Vec<u8>, Error> {
        let len = u16::try_from(message.len()).map_err(|_| {
            Error::Decode(rune_dns_wire::Error::MessageTooLong {
                len: message.len(),
                max: MAX_MESSAGE_LEN,
            })
        })?;
        let mut out = Vec::with_capacity(message.len() + 2);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(message);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn zone() -> Name {
        Name::from_ascii("example.com").unwrap()
    }

    fn soa(serial: u32) -> Record {
        Record::new(
            zone(),
            3600,
            RData::Soa(Soa {
                mname: Name::from_ascii("ns.example.com").unwrap(),
                rname: Name::from_ascii("h.example.com").unwrap(),
                serial,
                refresh: 1,
                retry: 2,
                expire: 3,
                minimum: 4,
            }),
        )
    }

    fn a(last: u8) -> Record {
        Record::new(
            Name::from_ascii("www.example.com").unwrap(),
            60,
            RData::A(Ipv4Addr::new(192, 0, 2, last)),
        )
    }

    fn response(records: &[Record]) -> Message {
        let query = axfr_query(1, zone());
        records
            .iter()
            .fold(Message::response_to(&query), |message, record| {
                message.with_answer(record.clone())
            })
    }

    fn ixfr_response(records: &[Record]) -> Message {
        let RData::Soa(current) = soa(1).data else {
            unreachable!()
        };
        let query = ixfr_query(1, zone(), current);
        records
            .iter()
            .fold(Message::response_to(&query), |message, record| {
                message.with_answer(record.clone())
            })
    }

    fn elsewhere() -> Record {
        Record::new(
            Name::from_ascii("www.example.org").unwrap(),
            60,
            RData::A(Ipv4Addr::new(203, 0, 113, 1)),
        )
    }

    #[test]
    fn axfr_drops_records_outside_the_zone() {
        // A hostile primary must not be able to add names of other zones
        // to the transferred zone.
        let mut axfr = Axfr::new(zone()).with_id(1);
        let status = axfr
            .push(&response(&[soa(5), a(1), elsewhere(), soa(5)]))
            .unwrap();
        assert_eq!(status, Status::Done);
        assert_eq!(axfr.finish().unwrap().records, [soa(5), a(1)]);
    }

    #[test]
    fn ixfr_drops_records_outside_the_zone() {
        let mut full = Ixfr::new(zone(), 1).with_id(1);
        full.push(&ixfr_response(&[soa(3), elsewhere(), a(1), soa(3)]))
            .unwrap();
        let IxfrOutcome::Full(zone_data) = full.finish().unwrap() else {
            panic!("not a full transfer");
        };
        assert_eq!(zone_data.records, [soa(3), a(1)]);

        let mut diff = Ixfr::new(zone(), 1).with_id(1);
        diff.push(&ixfr_response(&[
            soa(2),
            soa(1),
            elsewhere(),
            a(1),
            soa(2),
            elsewhere(),
            a(2),
            soa(2),
        ]))
        .unwrap();
        let IxfrOutcome::Incremental { diffs, .. } = diff.finish().unwrap() else {
            panic!("not incremental");
        };
        assert_eq!(diffs[0].removed, [a(1)]);
        assert_eq!(diffs[0].added, [a(2)]);
    }

    #[test]
    fn axfr_one_record_per_message() {
        let mut axfr = Axfr::new(zone()).with_id(1);
        let stream = [soa(5), a(1), a(2), soa(5)];
        for (index, record) in stream.iter().enumerate() {
            let mut message = response(core::slice::from_ref(record));
            if index > 0 {
                message.questions.clear();
            }
            let status = axfr.push(&message).unwrap();
            assert_eq!(status == Status::Done, index == 3);
        }
        assert_eq!(axfr.finish().unwrap().records, [soa(5), a(1), a(2)]);
    }

    #[test]
    fn axfr_errors() {
        let refused = Message::response_to(&axfr_query(1, zone())).with_rcode(Rcode::REFUSED);
        assert_eq!(
            Axfr::new(zone()).push(&refused),
            Err(Error::Rcode(Rcode::REFUSED))
        );
        let reason = |result: Result<Status, Error>| match result {
            Err(Error::Transfer { reason }) => reason,
            other => panic!("{other:?}"),
        };
        assert_eq!(
            reason(Axfr::new(zone()).push(&response(&[a(1)]))),
            "first record is not the zone's SOA"
        );
        assert_eq!(
            reason(Axfr::new(zone()).push(&response(&[soa(1), a(1), soa(2)]))),
            "closing SOA serial differs from the opening one"
        );
        assert_eq!(
            reason(Axfr::new(zone()).push(&response(&[soa(1), soa(1), a(1)]))),
            "records after the closing SOA"
        );
        assert_eq!(
            reason(Axfr::new(zone()).with_id(2).push(&response(&[soa(1)]))),
            "response id does not match the query"
        );
        assert_eq!(
            reason(Axfr::new(zone()).push(&axfr_query(1, zone()))),
            "message is not a response"
        );
        assert_eq!(
            reason(Axfr::new(zone()).push(&response(&[]))),
            "first response has no answer records"
        );
        let mut other = response(&[soa(1)]);
        other.questions[0].name = Name::from_ascii("example.net").unwrap();
        assert_eq!(
            reason(Axfr::new(zone()).push(&other)),
            "question does not match the transfer"
        );
        let mut axfr = Axfr::new(zone());
        axfr.push(&response(&[soa(1), soa(1)])).unwrap();
        assert_eq!(
            reason(axfr.push(&response(&[soa(1)]))),
            "message after the end of the transfer"
        );
        let mut axfr = Axfr::new(zone());
        axfr.push(&response(&[soa(1), a(1)])).unwrap();
        assert!(!axfr.is_done());
        assert_eq!(axfr.records().len(), 2);
        assert!(axfr.finish().is_err());

        let mut capped = Axfr::new(zone()).with_max_records(2);
        assert_eq!(
            capped.push(&response(&[soa(1), a(1), a(2)])),
            Err(Error::TooManyRecords { max: 2 })
        );
        assert!(matches!(
            Axfr::new(zone()).push_bytes(&[0; 5]),
            Err(Error::Decode(_))
        ));
    }

    #[test]
    fn ixfr_up_to_date() {
        let mut ixfr = Ixfr::new(zone(), 1);
        assert_eq!(ixfr.push(&ixfr_response(&[soa(1)])).unwrap(), Status::Done);
        assert_eq!(ixfr.finish().unwrap(), IxfrOutcome::UpToDate(soa(1)));
        // A newer lone SOA may be the start of a one-record-per-message
        // stream: wait for more.
        let mut ixfr = Ixfr::new(zone(), 1);
        assert_eq!(ixfr.push(&ixfr_response(&[soa(3)])).unwrap(), Status::More);
        assert!(ixfr.clone().finish().is_err());
        let mut rest = ixfr_response(&[a(1), soa(3)]);
        rest.questions.clear();
        assert_eq!(ixfr.push(&rest).unwrap(), Status::Done);
        assert_eq!(
            ixfr.finish().unwrap(),
            IxfrOutcome::Full(Zone::new(vec![soa(3), a(1)]))
        );
    }

    #[test]
    fn ixfr_full_fallback() {
        let mut ixfr = Ixfr::new(zone(), 1);
        ixfr.push(&ixfr_response(&[soa(3), a(1), a(2), soa(3)]))
            .unwrap();
        assert_eq!(
            ixfr.finish().unwrap(),
            IxfrOutcome::Full(Zone::new(vec![soa(3), a(1), a(2)]))
        );
        let mut ixfr = Ixfr::new(zone(), 1);
        ixfr.push(&ixfr_response(&[soa(3), soa(3)])).unwrap();
        assert_eq!(
            ixfr.finish().unwrap(),
            IxfrOutcome::Full(Zone::new(vec![soa(3)]))
        );
    }

    #[test]
    fn ixfr_incremental_chain() {
        // RFC 1995 §7 shape: 1 -> 2 -> 3.
        let records = [
            soa(3),
            soa(1),
            a(1),
            soa(2),
            a(2),
            soa(2),
            a(2),
            soa(3),
            a(3),
            soa(3),
        ];
        let mut ixfr = Ixfr::new(zone(), 1).with_id(1);
        // Split over three messages.
        for (index, chunk) in records.chunks(4).enumerate() {
            let status = ixfr.push(&ixfr_response(chunk)).unwrap();
            assert_eq!(status == Status::Done, index == 2);
        }
        let IxfrOutcome::Incremental { soa: newest, diffs } = ixfr.finish().unwrap() else {
            panic!("not incremental")
        };
        assert_eq!(newest, soa(3));
        assert_eq!(
            diffs,
            [
                IxfrDiff {
                    from: soa(1),
                    to: soa(2),
                    removed: vec![a(1)],
                    added: vec![a(2)],
                },
                IxfrDiff {
                    from: soa(2),
                    to: soa(3),
                    removed: vec![a(2)],
                    added: vec![a(3)],
                },
            ]
        );

        let broken = [soa(3), soa(1), soa(2), soa(5), soa(3)];
        assert_eq!(
            Ixfr::new(zone(), 1).push(&ixfr_response(&broken)),
            Err(Error::Transfer {
                reason: "IXFR difference sequences do not chain"
            })
        );
        let trailing = [soa(2), soa(1), soa(2), soa(2), a(1)];
        assert_eq!(
            Ixfr::new(zone(), 1).push(&ixfr_response(&trailing)),
            Err(Error::Transfer {
                reason: "records after the closing SOA"
            })
        );
    }

    #[test]
    fn foreign_soa_is_rejected() {
        let mut foreign = soa(1);
        foreign.name = Name::from_ascii("example.net").unwrap();
        assert_eq!(
            Axfr::new(zone()).push(&response(&[soa(1), foreign])),
            Err(Error::Transfer {
                reason: "SOA record of another zone"
            })
        );
    }

    #[test]
    fn serial_arithmetic() {
        assert!(serial_newer(2, 1));
        assert!(!serial_newer(1, 1));
        assert!(!serial_newer(1, 2));
        assert!(serial_newer(0, u32::MAX));
        assert!(!serial_newer(u32::MAX, 0));
    }

    #[test]
    fn frames() {
        let mut frames = TcpFrames::new();
        let mut stream = TcpFrames::frame(b"one").unwrap();
        stream.extend(TcpFrames::frame(b"").unwrap());
        stream.extend(TcpFrames::frame(b"three").unwrap());
        for byte in &stream {
            frames.push(core::slice::from_ref(byte));
        }
        assert_eq!(frames.next_frame().unwrap(), b"one");
        assert_eq!(frames.next_frame().unwrap(), b"");
        assert_eq!(frames.next_frame().unwrap(), b"three");
        assert_eq!(frames.next_frame(), None);
        assert_eq!(frames.buffered(), 0);
        assert!(TcpFrames::frame(&vec![0; 65_536]).is_err());
    }
}

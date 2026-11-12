//! Messages: header, sections and EDNS(0) (RFC 1035 §4, RFC 6891).

use core::fmt;

use crate::name::Name;
use crate::rdata::RData;
use crate::types::{Class, Opcode, Rcode, RecordType};
use crate::wire::{Reader, Writer};
use crate::{Error, MAX_MESSAGE_LEN};

/// The message header (RFC 1035 §4.1.1), without the section counts, which
/// come from the sections themselves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "one field per header flag bit, as RFC 1035 lays them out"
)]
pub struct Header {
    /// Transaction id, echoed in the response.
    pub id: u16,
    /// `QR`: this is a response.
    pub response: bool,
    /// Kind of query.
    pub opcode: Opcode,
    /// `AA`: the answer is authoritative.
    pub authoritative: bool,
    /// `TC`: the message was truncated.
    pub truncated: bool,
    /// `RD`: recursion desired.
    pub recursion_desired: bool,
    /// `RA`: recursion available.
    pub recursion_available: bool,
    /// The reserved `Z` bit; must be zero, kept so messages round-trip.
    pub z: bool,
    /// `AD`: authentic data (RFC 4035).
    pub authentic_data: bool,
    /// `CD`: checking disabled (RFC 4035).
    pub checking_disabled: bool,
    /// The full response code: the header's 4 bits, extended by the `OPT`
    /// record's 8 bits when [`Message::edns`] is set (RFC 6891 §6.1.3).
    pub rcode: Rcode,
}

impl Header {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, Error> {
        let id = reader.u16()?;
        let flags = reader.u16()?;
        let bit = |n: u16| flags & (1 << n) != 0;
        Ok(Self {
            id,
            response: bit(15),
            opcode: Opcode(((flags >> 11) & 0xF) as u8),
            authoritative: bit(10),
            truncated: bit(9),
            recursion_desired: bit(8),
            recursion_available: bit(7),
            z: bit(6),
            authentic_data: bit(5),
            checking_disabled: bit(4),
            rcode: Rcode(flags & 0xF),
        })
    }

    fn flags(&self) -> Result<u16, Error> {
        if self.opcode.0 > 0xF {
            return Err(Error::OutOfRange {
                field: "opcode",
                value: self.opcode.0.into(),
            });
        }
        let bit = |set: bool, n: u16| if set { 1 << n } else { 0 };
        Ok(bit(self.response, 15)
            | u16::from(self.opcode.0) << 11
            | bit(self.authoritative, 10)
            | bit(self.truncated, 9)
            | bit(self.recursion_desired, 8)
            | bit(self.recursion_available, 7)
            | bit(self.z, 6)
            | bit(self.authentic_data, 5)
            | bit(self.checking_disabled, 4)
            | (self.rcode.0 & 0xF))
    }
}

/// An entry of the question section (RFC 1035 §4.1.2).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Question {
    /// The name asked about.
    pub name: Name,
    /// The type asked for.
    pub qtype: RecordType,
    /// The class asked for.
    pub qclass: Class,
}

impl Question {
    /// A question for `qtype` records of `name` in class `IN`.
    #[must_use]
    pub const fn new(name: Name, qtype: RecordType) -> Self {
        Self {
            name,
            qtype,
            qclass: Class::IN,
        }
    }

    /// Sets the class.
    #[must_use]
    pub const fn with_class(mut self, qclass: Class) -> Self {
        self.qclass = qclass;
        self
    }
}

impl fmt::Display for Question {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}", self.name, self.qclass, self.qtype)
    }
}

/// A resource record (RFC 1035 §4.1.3). Its type is [`Record::rtype`],
/// taken from the data.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Record {
    /// Owner name.
    pub name: Name,
    /// Class, usually `IN`.
    pub class: Class,
    /// Time to live, in seconds.
    pub ttl: u32,
    /// Type and data.
    pub data: RData,
}

impl Record {
    /// A record of class `IN`.
    #[must_use]
    pub const fn new(name: Name, ttl: u32, data: RData) -> Self {
        Self {
            name,
            class: Class::IN,
            ttl,
            data,
        }
    }

    /// Sets the class.
    #[must_use]
    pub const fn with_class(mut self, class: Class) -> Self {
        self.class = class;
        self
    }

    /// The record type.
    #[must_use]
    pub const fn rtype(&self) -> RecordType {
        self.data.rtype()
    }

    fn encode(&self, writer: &mut Writer) -> Result<(), Error> {
        writer.name(&self.name, true);
        writer.u16(self.rtype().0);
        writer.u16(self.class.0);
        writer.u32(self.ttl);
        rdata(writer, |writer| self.data.encode(writer))
    }
}

impl fmt::Display for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {} {}",
            self.name,
            self.ttl,
            self.class,
            self.rtype(),
            self.data
        )
    }
}

/// An EDNS(0) option (RFC 6891 §6.1.2), kept as opaque bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EdnsOption {
    /// Option code.
    pub code: u16,
    /// Option data.
    pub data: Vec<u8>,
}

impl EdnsOption {
    /// Name server identifier (RFC 5001).
    pub const NSID: u16 = 3;
    /// Client subnet (RFC 7871).
    pub const CLIENT_SUBNET: u16 = 8;
    /// DNS cookie (RFC 7873).
    pub const COOKIE: u16 = 10;
    /// TCP keepalive (RFC 7828).
    pub const TCP_KEEPALIVE: u16 = 11;
    /// Padding (RFC 7830).
    pub const PADDING: u16 = 12;
    /// Extended DNS error (RFC 8914).
    pub const EXTENDED_ERROR: u16 = 15;

    /// An option with `code` and `data`.
    #[must_use]
    pub const fn new(code: u16, data: Vec<u8>) -> Self {
        Self { code, data }
    }
}

/// The EDNS(0) parameters carried by an `OPT` pseudo-record
/// (RFC 6891 §6). The extended `RCODE` bits live in [`Header::rcode`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Edns {
    /// Largest UDP payload the sender can receive.
    pub udp_payload_size: u16,
    /// EDNS version; only 0 is defined.
    pub version: u8,
    /// The 16 flag bits, `DO` (`0x8000`) included.
    pub flags: u16,
    /// Options, in wire order.
    pub options: Vec<EdnsOption>,
}

impl Default for Edns {
    /// Version 0, no flags, no options, and a 1232-octet payload size, the
    /// value the DNS flag day 2020 recommends.
    fn default() -> Self {
        Self {
            udp_payload_size: 1232,
            version: 0,
            flags: 0,
            options: Vec::new(),
        }
    }
}

impl Edns {
    const DO: u16 = 0x8000;

    /// The `DO` bit: the sender wants DNSSEC records (RFC 3225).
    #[must_use]
    pub const fn dnssec_ok(&self) -> bool {
        self.flags & Self::DO != 0
    }

    /// Sets the `DO` bit.
    #[must_use]
    pub const fn with_dnssec_ok(mut self, dnssec_ok: bool) -> Self {
        if dnssec_ok {
            self.flags |= Self::DO;
        } else {
            self.flags &= !Self::DO;
        }
        self
    }

    /// Sets the UDP payload size.
    #[must_use]
    pub const fn with_udp_payload_size(mut self, size: u16) -> Self {
        self.udp_payload_size = size;
        self
    }

    /// Adds an option.
    #[must_use]
    pub fn with_option(mut self, option: EdnsOption) -> Self {
        self.options.push(option);
        self
    }

    /// Decodes the `OPT` record whose owner, class and TTL have been read.
    fn decode(
        class: u16,
        ttl: u32,
        reader: &mut Reader<'_>,
        header_rcode: Rcode,
    ) -> Result<(Self, Rcode), Error> {
        let [extended_rcode, version, flags_high, flags_low] = ttl.to_be_bytes();
        let mut options = Vec::new();
        while reader.remaining() > 0 {
            let code = reader.u16()?;
            let len = reader.u16()?;
            let data = reader.bytes(usize::from(len))?.to_vec();
            options.push(EdnsOption { code, data });
        }
        let rcode = Rcode(u16::from(extended_rcode) << 4 | header_rcode.0);
        let edns = Self {
            udp_payload_size: class,
            version,
            flags: u16::from_be_bytes([flags_high, flags_low]),
            options,
        };
        Ok((edns, rcode))
    }

    fn encode(&self, rcode: Rcode, writer: &mut Writer) -> Result<(), Error> {
        let extended = u8::try_from(rcode.0 >> 4).map_err(|_| Error::OutOfRange {
            field: "rcode",
            value: rcode.0.into(),
        })?;
        let [flags_high, flags_low] = self.flags.to_be_bytes();
        writer.u8(0); // root owner
        writer.u16(RecordType::OPT.0);
        writer.u16(self.udp_payload_size);
        writer.u32(u32::from_be_bytes([
            extended,
            self.version,
            flags_high,
            flags_low,
        ]));
        rdata(writer, |writer| {
            for option in &self.options {
                let len = u16::try_from(option.data.len()).map_err(|_| Error::RdataTooLong {
                    len: option.data.len(),
                })?;
                writer.u16(option.code);
                writer.u16(len);
                writer.bytes(&option.data);
            }
            Ok(())
        })
    }
}

/// Writes an RDLENGTH placeholder, the RDATA, then patches the length.
fn rdata(
    writer: &mut Writer,
    body: impl FnOnce(&mut Writer) -> Result<(), Error>,
) -> Result<(), Error> {
    let at = writer.len();
    writer.u16(0);
    body(writer)?;
    let len = writer.len() - at - 2;
    let len = u16::try_from(len).map_err(|_| Error::RdataTooLong { len })?;
    writer.set_u16(at, len);
    Ok(())
}

/// A DNS message.
///
/// Decoding lifts the `OPT` pseudo-record out of the additional section
/// into [`Message::edns`]; encoding writes it back as the last additional
/// record. Section counts are not stored: they are the lengths of the
/// section vectors.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct Message {
    /// Header fields.
    pub header: Header,
    /// Question section.
    pub questions: Vec<Question>,
    /// Answer section.
    pub answers: Vec<Record>,
    /// Authority section.
    pub authorities: Vec<Record>,
    /// Additional section, without the `OPT` record.
    pub additionals: Vec<Record>,
    /// EDNS(0) parameters, from the `OPT` record if there is one.
    pub edns: Option<Edns>,
}

/// The smallest possible record: root owner, type, class, TTL, RDLENGTH.
const MIN_RECORD_LEN: usize = 11;
/// The smallest possible question: root name, type, class.
const MIN_QUESTION_LEN: usize = 5;

/// Which section a record goes into.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    Answer,
    Authority,
    Additional,
}

impl Message {
    /// A standard query for `question`, with `RD` set.
    #[must_use]
    pub fn query(id: u16, question: Question) -> Self {
        Self {
            header: Header {
                id,
                recursion_desired: true,
                ..Header::default()
            },
            questions: vec![question],
            ..Self::default()
        }
    }

    /// An empty `NOERROR` response to `query`: same id, opcode, questions,
    /// `RD` and `CD`, with `QR` set. If the query carried EDNS(0), the
    /// response does too ([`Edns::default`], with the query's `DO` bit), as
    /// RFC 6891 §6.1.1 and RFC 3225 §3 require.
    #[must_use]
    pub fn response_to(query: &Self) -> Self {
        Self {
            header: Header {
                id: query.header.id,
                response: true,
                opcode: query.header.opcode,
                recursion_desired: query.header.recursion_desired,
                checking_disabled: query.header.checking_disabled,
                ..Header::default()
            },
            questions: query.questions.clone(),
            edns: query
                .edns
                .as_ref()
                .map(|edns| Edns::default().with_dnssec_ok(edns.dnssec_ok())),
            ..Self::default()
        }
    }

    /// Sets the transaction id.
    #[must_use]
    pub const fn with_id(mut self, id: u16) -> Self {
        self.header.id = id;
        self
    }

    /// Sets the response code. Codes above 15 need [`Message::edns`].
    #[must_use]
    pub const fn with_rcode(mut self, rcode: Rcode) -> Self {
        self.header.rcode = rcode;
        self
    }

    /// Sets `AA`.
    #[must_use]
    pub const fn with_authoritative(mut self, authoritative: bool) -> Self {
        self.header.authoritative = authoritative;
        self
    }

    /// Sets `RD`.
    #[must_use]
    pub const fn with_recursion_desired(mut self, recursion_desired: bool) -> Self {
        self.header.recursion_desired = recursion_desired;
        self
    }

    /// Sets `RA`.
    #[must_use]
    pub const fn with_recursion_available(mut self, recursion_available: bool) -> Self {
        self.header.recursion_available = recursion_available;
        self
    }

    /// Adds a question.
    #[must_use]
    pub fn with_question(mut self, question: Question) -> Self {
        self.questions.push(question);
        self
    }

    /// Adds an answer record.
    #[must_use]
    pub fn with_answer(mut self, record: Record) -> Self {
        self.answers.push(record);
        self
    }

    /// Adds an authority record.
    #[must_use]
    pub fn with_authority(mut self, record: Record) -> Self {
        self.authorities.push(record);
        self
    }

    /// Adds an additional record.
    #[must_use]
    pub fn with_additional(mut self, record: Record) -> Self {
        self.additionals.push(record);
        self
    }

    /// Sets the EDNS(0) parameters.
    #[must_use]
    pub fn with_edns(mut self, edns: Edns) -> Self {
        self.edns = Some(edns);
        self
    }

    /// Parses a whole message.
    ///
    /// # Errors
    ///
    /// Any [`Error`] describing malformed input; see the crate docs for the
    /// rules. The decoder never panics and never reads past `bytes`.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        let header = Header::decode(&mut reader)?;
        let counts = [reader.u16()?, reader.u16()?, reader.u16()?, reader.u16()?];
        let [questions_len, answers_len, authorities_len, additionals_len] =
            counts.map(usize::from);

        let mut questions =
            Vec::with_capacity(questions_len.min(reader.remaining() / MIN_QUESTION_LEN));
        for _ in 0..questions_len {
            questions.push(Question {
                name: reader.name()?,
                qtype: RecordType(reader.u16()?),
                qclass: Class(reader.u16()?),
            });
        }

        let mut message = Self {
            header,
            questions,
            ..Self::default()
        };
        for (section, count) in [
            (Section::Answer, answers_len),
            (Section::Authority, authorities_len),
            (Section::Additional, additionals_len),
        ] {
            let mut records = Vec::with_capacity(count.min(reader.remaining() / MIN_RECORD_LEN));
            for _ in 0..count {
                if let Some(record) = message.decode_record(&mut reader, section)? {
                    records.push(record);
                }
            }
            match section {
                Section::Answer => message.answers = records,
                Section::Authority => message.authorities = records,
                Section::Additional => message.additionals = records,
            }
        }

        if reader.remaining() > 0 {
            return Err(Error::TrailingData {
                offset: reader.pos(),
                len: reader.remaining(),
            });
        }
        Ok(message)
    }

    /// Decodes one record. An `OPT` record is stored in `self.edns` (and
    /// its extended `RCODE` in `header`) instead of being returned.
    fn decode_record(
        &mut self,
        reader: &mut Reader<'_>,
        section: Section,
    ) -> Result<Option<Record>, Error> {
        let name = reader.name()?;
        let rtype = RecordType(reader.u16()?);
        let class = reader.u16()?;
        let ttl = reader.u32()?;
        let len = usize::from(reader.u16()?);
        let mut rdata = reader.sub(len)?;
        if rtype == RecordType::OPT && section == Section::Additional {
            if self.edns.is_some() {
                return Err(Error::InvalidOpt {
                    reason: "more than one OPT record",
                });
            }
            if !name.is_root() {
                return Err(Error::InvalidOpt {
                    reason: "owner is not the root",
                });
            }
            let (edns, rcode) = Edns::decode(class, ttl, &mut rdata, self.header.rcode)?;
            self.edns = Some(edns);
            self.header.rcode = rcode;
            return Ok(None);
        }
        let data = RData::decode(rtype, &mut rdata)?;
        Ok(Some(Record {
            name,
            class: Class(class),
            ttl,
            data,
        }))
    }

    /// Encodes the message, compressing names.
    ///
    /// # Errors
    ///
    /// [`Error::MessageTooLong`] past 65 535 octets,
    /// [`Error::OutOfRange`] for an opcode above 15 or an `RCODE` that does
    /// not fit (above 15 without EDNS, above 4095 with it),
    /// [`Error::TooManyRecords`], and errors for RDATA that cannot be
    /// written ([`Error::CharacterStringTooLong`], [`Error::RdataTooLong`],
    /// [`Error::InvalidRdata`], [`Error::InvalidOpt`]).
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.encode_inner(MAX_MESSAGE_LEN, false)
    }

    /// Encodes the message in at most `max_len` octets, as a UDP responder
    /// must (RFC 1035 §4.2.1, RFC 6891 §7).
    ///
    /// If the whole message does not fit, records are dropped from the end:
    /// additional records first, then authority, then answer records. The
    /// `OPT` record is always kept. `TC` is set when an answer or authority
    /// record had to go; dropping only additional records leaves it clear
    /// (RFC 2181 §9).
    ///
    /// # Errors
    ///
    /// As [`Message::encode`], and [`Error::MessageTooLong`] if not even the
    /// header, questions and `OPT` record fit.
    pub fn encode_with_limit(&self, max_len: usize) -> Result<Vec<u8>, Error> {
        self.encode_inner(max_len.min(MAX_MESSAGE_LEN), true)
    }

    fn encode_inner(&self, max_len: usize, truncate: bool) -> Result<Vec<u8>, Error> {
        if self.edns.is_none() && self.header.rcode.0 > 0xF {
            return Err(Error::OutOfRange {
                field: "rcode",
                value: self.header.rcode.0.into(),
            });
        }
        let count =
            |len: usize| u16::try_from(len).map_err(|_| Error::TooManyRecords { count: len });
        let qdcount = count(self.questions.len())?;
        count(self.answers.len())?;
        count(self.authorities.len())?;
        count(self.additionals.len() + usize::from(self.edns.is_some()))?;

        let mut writer = Writer::new();
        writer.u16(self.header.id);
        writer.u16(self.header.flags()?);
        writer.u16(qdcount);
        writer.bytes(&[0; 6]); // ANCOUNT, NSCOUNT, ARCOUNT: patched below
        for question in &self.questions {
            writer.name(&question.name, true);
            writer.u16(question.qtype.0);
            writer.u16(question.qclass.0);
        }

        // Room kept for the OPT record, which goes last.
        let opt = match &self.edns {
            Some(edns) => {
                let mut scratch = Writer::new();
                edns.encode(self.header.rcode, &mut scratch)?;
                scratch.into_bytes()
            }
            None => Vec::new(),
        };
        let budget = max_len.saturating_sub(opt.len());
        writer
            .check_len(budget)
            .map_err(|_| Error::MessageTooLong {
                len: writer.len() + opt.len(),
                max: max_len,
            })?;

        let mut truncated = false;
        let mut counts = [0_u16; 3];
        let sections = [&self.answers, &self.authorities, &self.additionals];
        'sections: for (index, records) in sections.into_iter().enumerate() {
            for record in records {
                let mark = writer.len();
                record.encode(&mut writer)?;
                if writer.check_len(budget).is_err() {
                    if !truncate {
                        return Err(Error::MessageTooLong {
                            len: writer.len() + opt.len(),
                            max: max_len,
                        });
                    }
                    writer.truncate(mark);
                    truncated = index < 2;
                    break 'sections;
                }
                if let Some(slot) = counts.get_mut(index) {
                    *slot += 1;
                }
            }
        }
        writer.bytes(&opt);

        let [answers, authorities, additionals] = counts;
        writer.set_u16(6, answers);
        writer.set_u16(8, authorities);
        writer.set_u16(10, additionals + u16::from(self.edns.is_some()));
        if truncated {
            let flags = self.header.flags()? | 1 << 9;
            writer.set_u16(2, flags);
        }
        Ok(writer.into_bytes())
    }
}

impl fmt::Display for Message {
    /// A `dig`-like dump: header, then each non-empty section.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let h = &self.header;
        writeln!(
            f,
            ";; opcode: {}, status: {}, id: {}",
            h.opcode, h.rcode, h.id
        )?;
        let flags = [
            (h.response, "qr"),
            (h.authoritative, "aa"),
            (h.truncated, "tc"),
            (h.recursion_desired, "rd"),
            (h.recursion_available, "ra"),
            (h.authentic_data, "ad"),
            (h.checking_disabled, "cd"),
        ];
        f.write_str(";; flags:")?;
        for (set, text) in flags {
            if set {
                write!(f, " {text}")?;
            }
        }
        writeln!(f)?;
        if let Some(edns) = &self.edns {
            write!(
                f,
                ";; EDNS: version {}, udp {}",
                edns.version, edns.udp_payload_size
            )?;
            if edns.dnssec_ok() {
                f.write_str(", do")?;
            }
            writeln!(f)?;
        }
        if !self.questions.is_empty() {
            writeln!(f, ";; QUESTION")?;
            for question in &self.questions {
                writeln!(f, "{question}")?;
            }
        }
        for (title, records) in [
            ("ANSWER", &self.answers),
            ("AUTHORITY", &self.authorities),
            ("ADDITIONAL", &self.additionals),
        ] {
            if !records.is_empty() {
                writeln!(f, ";; {title}")?;
                for record in records {
                    writeln!(f, "{record}")?;
                }
            }
        }
        Ok(())
    }
}

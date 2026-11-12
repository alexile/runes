//! The sans-I/O core: sealing new records and verifying a stream of them.

use crate::{Digest, Entry, Error, Record, Signer, Tamper};

/// The head of a chain: the next sequence number and the hash the next
/// record links to. Seals entries into [`Record`]s without any I/O.
///
/// ```
/// use rune_audit_log::{Chain, Entry, Verifier};
///
/// let mut chain = Chain::new();
/// let first = chain.seal(Entry::new("alice", "login"), 1_700_000_000_000, None)?;
/// let second = chain.seal(Entry::new("alice", "logout"), 1_700_000_060_000, None)?;
/// assert_eq!(second.prev, first.hash);
///
/// let mut verifier = Verifier::new();
/// verifier.push(&first)?;
/// verifier.push(&second)?;
/// assert_eq!(verifier.finish().head, chain.head());
/// # Ok::<(), rune_audit_log::Error>(())
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Chain {
    next_seq: u64,
    head: Digest,
}

impl Chain {
    /// An empty chain: the first record gets sequence 0 and links to
    /// [`Digest::GENESIS`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            next_seq: 0,
            head: Digest::GENESIS,
        }
    }

    /// Continues after `last`, the newest record of an existing log.
    ///
    /// # Errors
    ///
    /// [`Error::Tampered`] when `last`'s hash does not match its contents
    /// (continuing from it would bless a forged head), and
    /// [`Error::SequenceExhausted`] when its sequence is `u64::MAX`.
    pub fn resume(last: &Record) -> Result<Self, Error> {
        if !last.hash_is_valid() {
            return Err(Error::Tampered {
                seq: last.seq,
                kind: Tamper::HashMismatch,
            });
        }
        Ok(Self {
            next_seq: last.seq.checked_add(1).ok_or(Error::SequenceExhausted)?,
            head: last.hash,
        })
    }

    /// The sequence number the next record gets.
    #[must_use]
    pub const fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// The hash of the newest record, or [`Digest::GENESIS`].
    #[must_use]
    pub const fn head(&self) -> Digest {
        self.head
    }

    /// Seals `entry` at `ts` (milliseconds since the Unix epoch) into the
    /// next record, signing it with `signer` if given, and advances the
    /// chain.
    ///
    /// # Errors
    ///
    /// [`Error::SequenceExhausted`] after `u64::MAX` records.
    pub fn seal(
        &mut self,
        entry: Entry,
        ts: u64,
        signer: Option<&dyn Signer>,
    ) -> Result<Record, Error> {
        let seq = self.next_seq;
        let next_seq = seq.checked_add(1).ok_or(Error::SequenceExhausted)?;
        let hash = Record::compute_hash(seq, ts, &entry, &self.head);
        let record = Record {
            seq,
            ts,
            entry,
            prev: self.head,
            hash,
            sig: signer.map(|signer| signer.sign(&hash)),
        };
        self.next_seq = next_seq;
        self.head = hash;
        Ok(record)
    }
}

/// The outcome of a successful verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Verified {
    /// How many records were checked.
    pub count: u64,
    /// The hash of the last record, or the starting hash if there were
    /// none. Keep it somewhere the log's writer cannot change (a
    /// separate system, a printed report) and pass it to
    /// [`Verifier::expect_head`] later: that is what detects a log whose
    /// newest records were deleted.
    pub head: Digest,
}

/// Checks records one at a time, in order, holding only the previous
/// hash: memory stays constant however long the log is.
///
/// Each record must carry the next sequence number, link to the previous
/// record's hash, and hash to its own [`hash`](Record::hash). With a
/// signer, each must also carry a valid signature.
#[derive(Clone, Copy)]
pub struct Verifier<'a> {
    expected_seq: u64,
    prev: Digest,
    count: u64,
    signer: Option<&'a dyn Signer>,
}

impl std::fmt::Debug for Verifier<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Verifier")
            .field("expected_seq", &self.expected_seq)
            .field("prev", &self.prev)
            .field("count", &self.count)
            .field("signed", &self.signer.is_some())
            .finish()
    }
}

impl Default for Verifier<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> Verifier<'a> {
    /// A verifier for a whole log, starting at sequence 0 and
    /// [`Digest::GENESIS`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            expected_seq: 0,
            prev: Digest::GENESIS,
            count: 0,
            signer: None,
        }
    }

    /// A verifier for the part of a log after a trusted checkpoint: the
    /// first record must have sequence `seq` and link to `prev`.
    #[must_use]
    pub const fn starting_at(seq: u64, prev: Digest) -> Self {
        Self {
            expected_seq: seq,
            prev,
            count: 0,
            signer: None,
        }
    }

    /// Requires every record to be signed by `signer`.
    #[must_use]
    pub const fn with_signer(mut self, signer: &'a dyn Signer) -> Self {
        self.signer = Some(signer);
        self
    }

    /// Checks the next record.
    ///
    /// # Errors
    ///
    /// [`Error::Tampered`] naming the record and what is wrong with it.
    /// After an error the verifier's state is unchanged.
    pub fn push(&mut self, record: &Record) -> Result<(), Error> {
        let fail = |kind| Error::Tampered {
            seq: record.seq,
            kind,
        };
        if record.seq != self.expected_seq {
            return Err(fail(Tamper::Sequence {
                expected: self.expected_seq,
            }));
        }
        if record.prev != self.prev {
            return Err(fail(Tamper::BrokenLink));
        }
        if !record.hash_is_valid() {
            return Err(fail(Tamper::HashMismatch));
        }
        if let Some(signer) = self.signer {
            match &record.sig {
                None => return Err(fail(Tamper::MissingSignature)),
                Some(sig) if !signer.verify(&record.hash, sig) => {
                    return Err(fail(Tamper::BadSignature));
                }
                Some(_) => {}
            }
        }
        // A record at u64::MAX can be verified; nothing may follow it.
        self.expected_seq = record.seq.wrapping_add(1);
        self.prev = record.hash;
        self.count += 1;
        Ok(())
    }

    /// The summary so far.
    #[must_use]
    pub const fn finish(&self) -> Verified {
        Verified {
            count: self.count,
            head: self.prev,
        }
    }

    /// Like [`finish`](Self::finish), but also requires the last hash to
    /// be `head`, a value recorded earlier outside the log.
    ///
    /// # Errors
    ///
    /// [`Error::Tampered`] with [`Tamper::HeadMismatch`] when the log
    /// ends anywhere else, for instance because records were removed
    /// from its end.
    pub fn expect_head(&self, head: &Digest) -> Result<Verified, Error> {
        if self.prev == *head {
            Ok(self.finish())
        } else {
            Err(Error::Tampered {
                seq: self.expected_seq,
                kind: Tamper::HeadMismatch,
            })
        }
    }
}

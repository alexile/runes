//! [`AuditLog`]: a chain bound to a store.

use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{Chain, Digest, Entry, Error, Record, Signer, Store, Verified, Verifier};

/// An append-only audit log over a [`Store`].
///
/// ```
/// use rune_audit_log::{AuditLog, Entry, HmacSha256, MemoryStore};
///
/// let mut log = AuditLog::open(MemoryStore::new())?
///     .with_signer(HmacSha256::new(b"audit key"));
/// log.append_at(Entry::new("alice", "login"), 1_700_000_000_000)?;
/// log.append_at(Entry::new("alice", "secret.read").with_target("db"), 1_700_000_001_000)?;
/// assert_eq!(log.verify()?.count, 2);
///
/// // Change one stored record: verification fails at that record.
/// let mut store = log.into_store();
/// store.records_mut()[0].entry.actor = "mallory".into();
/// let log = AuditLog::open(store)?;
/// assert!(log.verify().is_err());
/// # Ok::<(), rune_audit_log::Error>(())
/// ```
pub struct AuditLog<S> {
    store: S,
    chain: Chain,
    signer: Option<Box<dyn Signer + Send + Sync>>,
}

impl<S: std::fmt::Debug> std::fmt::Debug for AuditLog<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditLog")
            .field("store", &self.store)
            .field("chain", &self.chain)
            .field("signed", &self.signer.is_some())
            .finish()
    }
}

impl<S: Store> AuditLog<S> {
    /// Opens a log over `store`, continuing after its newest record.
    ///
    /// Only the newest record is checked here (its hash must match its
    /// contents); call [`verify`](Self::verify) to check the whole chain.
    ///
    /// # Errors
    ///
    /// Storage errors, and [`Error::Tampered`] when the newest record's
    /// hash is wrong.
    pub fn open(store: S) -> Result<Self, Error> {
        let chain = match store.last()? {
            Some(last) => Chain::resume(&last)?,
            None => Chain::new(),
        };
        Ok(Self {
            store,
            chain,
            signer: None,
        })
    }

    /// Signs every appended record with `signer` and requires valid
    /// signatures on every record in [`verify`](Self::verify).
    #[must_use]
    pub fn with_signer(mut self, signer: impl Signer + Send + Sync + 'static) -> Self {
        self.signer = Some(Box::new(signer));
        self
    }

    /// Appends `entry` stamped with the current system time.
    ///
    /// # Errors
    ///
    /// As for [`append_at`](Self::append_at).
    pub fn append(&mut self, entry: Entry) -> Result<Record, Error> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| {
                u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
            });
        self.append_at(entry, now)
    }

    /// Appends `entry` stamped `ts` (milliseconds since the Unix epoch)
    /// and returns the stored record.
    ///
    /// The chain advances only once the store accepted the record, so a
    /// failed append can be retried.
    ///
    /// # Errors
    ///
    /// Storage errors and [`Error::SequenceExhausted`].
    pub fn append_at(&mut self, entry: Entry, ts: u64) -> Result<Record, Error> {
        let mut next = self.chain;
        let signer = self.signer.as_deref().map(|signer| signer as &dyn Signer);
        let record = next.seal(entry, ts, signer)?;
        self.store.append(&record)?;
        self.chain = next;
        Ok(record)
    }

    /// Checks the whole log, streaming it from the store.
    ///
    /// # Errors
    ///
    /// [`Error::Tampered`] at the first bad record, storage errors, and
    /// [`Error::Tampered`] with [`Tamper::HeadMismatch`](crate::Tamper)
    /// when the stored log ends somewhere other than this log's head
    /// (records were removed or added behind its back).
    pub fn verify(&self) -> Result<Verified, Error> {
        self.verify_against(&self.chain.head())
    }

    /// Like [`verify`](Self::verify), but requires the log to end at
    /// `head`, a value saved earlier from [`head`](Self::head) somewhere
    /// the log's writer cannot change. This is what catches deleted tail
    /// records.
    ///
    /// # Errors
    ///
    /// As for [`verify`](Self::verify).
    pub fn verify_against(&self, head: &Digest) -> Result<Verified, Error> {
        let mut verifier = Verifier::new();
        if let Some(signer) = self.signer.as_deref() {
            verifier = verifier.with_signer(signer);
        }
        for record in self.store.records()? {
            verifier.push(&record?)?;
        }
        verifier.expect_head(head)
    }

    /// Writes every record as one JSON line, oldest first, and returns
    /// how many were written. Records are not verified on the way.
    ///
    /// # Errors
    ///
    /// Storage and write errors.
    pub fn export_jsonl(&self, mut out: impl Write) -> Result<u64, Error> {
        let mut count = 0;
        for record in self.store.records()? {
            let line = record?.to_json()?;
            writeln!(out, "{line}").map_err(|source| Error::Io { path: None, source })?;
            count += 1;
        }
        Ok(count)
    }

    /// The hash of the newest record, or [`Digest::GENESIS`].
    #[must_use]
    pub const fn head(&self) -> Digest {
        self.chain.head()
    }

    /// The sequence number of the next record.
    #[must_use]
    pub const fn next_seq(&self) -> u64 {
        self.chain.next_seq()
    }

    /// The underlying store.
    #[must_use]
    pub const fn store(&self) -> &S {
        &self.store
    }

    /// Gives the store back.
    #[must_use]
    pub fn into_store(self) -> S {
        self.store
    }
}

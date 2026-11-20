//! Shared defences for the binary-format loaders (PDF, EPUB): a wall-clock
//! deadline, a decompression budget and a panic barrier.

use std::panic::{self, AssertUnwindSafe};
use std::time::{Duration, Instant};

use crate::error::LoadError;
use crate::limits::Limits;

/// Longest message kept from a parser error; hostile input can make them huge.
const MAX_MESSAGE: usize = 200;

/// Run `f`, turning a panic inside a third-party parser into
/// [`LoadError::Malformed`]. (A build with `panic = "abort"` still aborts.)
pub fn catch<T>(f: impl FnOnce() -> Result<T, LoadError>) -> Result<T, LoadError> {
    panic::catch_unwind(AssertUnwindSafe(f)).unwrap_or_else(|_| Err(malformed("parser panicked")))
}

pub fn malformed(message: impl std::fmt::Display) -> LoadError {
    let mut message = message.to_string();
    if message.len() > MAX_MESSAGE {
        let mut end = MAX_MESSAGE;
        while !message.is_char_boundary(end) {
            end -= 1;
        }
        message.truncate(end);
        message.push('…');
    }
    LoadError::Malformed {
        path: None,
        message,
    }
}

/// A wall-clock budget checked at safe points between units of work.
#[derive(Debug, Clone, Copy)]
pub struct Deadline {
    at: Option<Instant>,
    limit: Duration,
}

impl Deadline {
    pub fn start(limit: Duration) -> Self {
        Self {
            at: Instant::now().checked_add(limit),
            limit,
        }
    }

    pub fn check(&self) -> Result<(), LoadError> {
        match self.at {
            Some(at) if Instant::now() > at => Err(LoadError::TimedOut { limit: self.limit }),
            _ => Ok(()),
        }
    }
}

/// Bytes still allowed to be decompressed from one input.
#[derive(Debug, Clone, Copy)]
pub struct Budget {
    limit: u64,
    used: u64,
}

impl Budget {
    pub const fn new(limits: &Limits) -> Self {
        Self {
            limit: limits.max_decompressed_bytes,
            used: 0,
        }
    }

    #[cfg_attr(
        not(feature = "pdf"),
        allow(dead_code, reason = "used by the PDF loader")
    )]
    pub const fn limit(&self) -> u64 {
        self.limit
    }

    pub const fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.used)
    }

    #[cfg_attr(
        not(feature = "pdf"),
        allow(dead_code, reason = "used by the PDF loader")
    )]
    pub fn remaining_usize(&self) -> usize {
        usize::try_from(self.remaining()).unwrap_or(usize::MAX)
    }

    pub const fn exceeded(&self) -> LoadError {
        LoadError::DecompressedTooLarge { limit: self.limit }
    }

    /// Charge `bytes`, failing once the total passes the limit.
    pub const fn charge(&mut self, bytes: usize) -> Result<(), LoadError> {
        self.used = self.used.saturating_add(bytes as u64);
        if self.used > self.limit {
            Err(self.exceeded())
        } else {
            Ok(())
        }
    }
}

/// Add `len` content bytes to `total`, failing past [`Limits::max_total_bytes`].
pub const fn charge_output(
    total: &mut usize,
    len: usize,
    limits: &Limits,
) -> Result<(), LoadError> {
    *total = total.saturating_add(len);
    if *total > limits.max_total_bytes {
        Err(LoadError::OutputTooLarge {
            limit: limits.max_total_bytes,
        })
    } else {
        Ok(())
    }
}

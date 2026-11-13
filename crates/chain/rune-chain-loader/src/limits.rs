/// Resource limits applied by every loader.
///
/// Loaders read untrusted input, so all of these are **on by default**
/// ([`Limits::DEFAULT`]). Raise them with the `with_*` setters, or use
/// [`Limits::unlimited`] for fully trusted input.
///
/// # Example
///
/// ```rust
/// use rune_chain_loader::Limits;
///
/// let limits = Limits::default().with_max_file_bytes(1024 * 1024).with_max_depth(4);
/// assert_eq!(limits.max_file_bytes, 1024 * 1024);
/// assert_eq!(limits.max_files, Limits::DEFAULT.max_files);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Limits {
    /// Largest file (or reader, for whole-input loaders) read into memory.
    /// Default 16 MiB.
    pub max_file_bytes: u64,
    /// Largest single record: one JSON line or one CSV row. Default 1 MiB.
    pub max_record_bytes: usize,
    /// Most documents produced from one input. Default 1,000,000.
    pub max_records: usize,
    /// Most content bytes produced from one input, summed over all of its
    /// documents. Default 256 MiB.
    ///
    /// Only CSV can produce more content than it reads (every row repeats
    /// the column names), so only the CSV loader checks it. Without it a
    /// long header row and many tiny rows would expand a few hundred KB of
    /// input into gigabytes.
    pub max_total_bytes: usize,
    /// Most files a directory walk yields. Default 10,000.
    pub max_files: usize,
    /// Deepest subdirectory a walk descends into (0 = only the root
    /// directory's own entries). Default 32.
    pub max_depth: usize,
}

impl Limits {
    /// The defaults described on each field.
    pub const DEFAULT: Self = Self {
        max_file_bytes: 16 * 1024 * 1024,
        max_record_bytes: 1024 * 1024,
        max_records: 1_000_000,
        max_total_bytes: 256 * 1024 * 1024,
        max_files: 10_000,
        max_depth: 32,
    };

    /// No limits at all. Only for trusted input.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_file_bytes: u64::MAX,
            max_record_bytes: usize::MAX,
            max_records: usize::MAX,
            max_total_bytes: usize::MAX,
            max_files: usize::MAX,
            max_depth: usize::MAX,
        }
    }

    /// Set [`Limits::max_file_bytes`].
    #[must_use]
    pub const fn with_max_file_bytes(mut self, bytes: u64) -> Self {
        self.max_file_bytes = bytes;
        self
    }

    /// Set [`Limits::max_record_bytes`].
    #[must_use]
    pub const fn with_max_record_bytes(mut self, bytes: usize) -> Self {
        self.max_record_bytes = bytes;
        self
    }

    /// Set [`Limits::max_records`].
    #[must_use]
    pub const fn with_max_records(mut self, records: usize) -> Self {
        self.max_records = records;
        self
    }

    /// Set [`Limits::max_total_bytes`].
    #[must_use]
    pub const fn with_max_total_bytes(mut self, bytes: usize) -> Self {
        self.max_total_bytes = bytes;
        self
    }

    /// Set [`Limits::max_files`].
    #[must_use]
    pub const fn with_max_files(mut self, files: usize) -> Self {
        self.max_files = files;
        self
    }

    /// Set [`Limits::max_depth`].
    #[must_use]
    pub const fn with_max_depth(mut self, depth: usize) -> Self {
        self.max_depth = depth;
        self
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

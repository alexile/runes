//! File and reader helpers (requires the `std` feature).

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use crate::{Analysis, Analyzer, Histogram, Profiler, Window};

const READ_BUFFER: usize = 64 * 1024;

/// Reads `reader` to the end in fixed-size chunks, retrying on interrupts.
fn for_each_chunk<R: Read>(mut reader: R, mut f: impl FnMut(&[u8])) -> io::Result<()> {
    let mut buffer = vec![0u8; READ_BUFFER];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(n) => f(&buffer[..n]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

/// Streams a file and returns its Shannon entropy.
///
/// The file is read in 64 KiB chunks, so memory use does not grow with its
/// size.
///
/// # Errors
///
/// Returns an error if the file cannot be opened or read.
///
/// # Examples
///
/// ```rust,no_run
/// use rune_entropy::file_entropy;
/// use std::path::Path;
///
/// let score = file_entropy(Path::new("data.bin"))?;
/// println!("{score:.4}");
/// # Ok::<(), std::io::Error>(())
/// ```
pub fn file_entropy(path: &Path) -> io::Result<f64> {
    let mut hist = Histogram::new();
    for_each_chunk(File::open(path)?, |chunk| hist.update(chunk))?;
    Ok(hist.shannon())
}

/// Reads a file and returns per-block Shannon entropy scores.
///
/// Block `i` covers bytes `i * block_size .. (i + 1) * block_size`; the last
/// block may be shorter. Memory use is bounded by `block_size`. See
/// [`block_entropy`](crate::block_entropy).
///
/// # Errors
///
/// Returns an error if the file cannot be opened or read, or
/// [`io::ErrorKind::InvalidInput`] if `block_size` is zero.
///
/// # Examples
///
/// ```rust,no_run
/// use rune_entropy::{file_block_entropy, classify};
/// use std::path::Path;
///
/// let scores = file_block_entropy(Path::new("firmware.bin"), 512)?;
/// for (i, score) in scores.iter().enumerate() {
///     println!("block {i:>4} @ {:#08x}  {score:.4}  {}", i * 512, classify(*score));
/// }
/// # Ok::<(), std::io::Error>(())
/// ```
pub fn file_block_entropy(path: &Path, block_size: usize) -> io::Result<Vec<f64>> {
    reader_block_entropy(File::open(path)?, block_size)
}

/// Per-block Shannon entropy of everything `reader` yields.
///
/// # Errors
///
/// Returns any read error, or [`io::ErrorKind::InvalidInput`] if
/// `block_size` is zero.
///
/// # Examples
///
/// ```rust
/// let data = [0u8; 300];
/// let scores = rune_entropy::reader_block_entropy(&data[..], 128)?;
/// assert_eq!(scores, [0.0, 0.0, 0.0]);
/// # Ok::<(), std::io::Error>(())
/// ```
pub fn reader_block_entropy<R: Read>(reader: R, block_size: usize) -> io::Result<Vec<f64>> {
    if block_size == 0 {
        return Err(crate::Error::ZeroWindow.into());
    }
    let mut scores = Vec::new();
    let mut hist = Histogram::new();
    let mut filled = 0usize;
    for_each_chunk(reader, |mut chunk| {
        while !chunk.is_empty() {
            let take = (block_size - filled).min(chunk.len());
            hist.update(&chunk[..take]);
            filled += take;
            chunk = &chunk[take..];
            if filled == block_size {
                scores.push(hist.shannon());
                hist.clear();
                filled = 0;
            }
        }
    })?;
    if filled > 0 {
        scores.push(hist.shannon());
    }
    Ok(scores)
}

/// Runs an [`Analyzer`] over everything `reader` yields.
///
/// # Errors
///
/// Returns any read error.
///
/// # Examples
///
/// ```rust
/// let report = rune_entropy::analyze_reader(&b"abcd"[..])?;
/// assert_eq!(report.shannon, 2.0);
/// # Ok::<(), std::io::Error>(())
/// ```
pub fn analyze_reader<R: Read>(reader: R) -> io::Result<Analysis> {
    let mut analyzer = Analyzer::new();
    for_each_chunk(reader, |chunk| analyzer.update(chunk))?;
    Ok(analyzer.analysis())
}

/// Streams a file through an [`Analyzer`].
///
/// # Errors
///
/// Returns an error if the file cannot be opened or read.
///
/// # Examples
///
/// ```rust,no_run
/// let report = rune_entropy::analyze_file(std::path::Path::new("sample.bin"))?;
/// println!("{:.4} bits/byte, {}", report.shannon, report.assess());
/// # Ok::<(), std::io::Error>(())
/// ```
pub fn analyze_file(path: &Path) -> io::Result<Analysis> {
    analyze_reader(File::open(path)?)
}

/// Sliding-window entropy profile of everything `reader` yields, using at
/// most `window` bytes of buffer. See [`Profiler`] for the window layout.
///
/// # Errors
///
/// Returns any read error, or [`io::ErrorKind::InvalidInput`] if `window`
/// or `step` is zero.
///
/// # Examples
///
/// ```rust
/// let data = vec![0u8; 4096];
/// let profile = rune_entropy::profile_reader(&data[..], 1024, 1024)?;
/// assert_eq!(profile.len(), 4);
/// # Ok::<(), std::io::Error>(())
/// ```
pub fn profile_reader<R: Read>(reader: R, window: usize, step: usize) -> io::Result<Vec<Window>> {
    let mut profiler = Profiler::new(window, step)?;
    let mut out = Vec::new();
    for_each_chunk(reader, |chunk| profiler.push(chunk, |w| out.push(w)))?;
    profiler.finish(|w| out.push(w));
    Ok(out)
}

/// Sliding-window entropy profile of a file. See [`profile_reader`].
///
/// # Errors
///
/// Returns an error if the file cannot be opened or read, or if `window` or
/// `step` is zero.
///
/// # Examples
///
/// ```rust,no_run
/// use rune_entropy::{profile_file, regions_where};
///
/// let profile = profile_file(std::path::Path::new("firmware.bin"), 1024, 256)?;
/// for region in regions_where(&profile, |e| e >= 7.0, 4096) {
///     println!("{:#x}..{:#x}  mean {:.3}", region.start, region.end, region.mean_entropy);
/// }
/// # Ok::<(), std::io::Error>(())
/// ```
pub fn profile_file(path: &Path, window: usize, step: usize) -> io::Result<Vec<Window>> {
    profile_reader(File::open(path)?, window, step)
}

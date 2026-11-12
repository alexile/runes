//! Character- and bit-level analysis of a sample of tokens (session IDs,
//! CSRF tokens, reset codes), in the style of Burp Sequencer.

use rune_stats::dist::{chi_squared_sf, erfc};

use crate::battery::{self, Report};
use crate::nist::to_f64;
use crate::{Bits, Error};

/// Settings for [`analyze_tokens`].
#[derive(Debug, Clone, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct TokenOptions {
    /// The symbols tokens are drawn from. `None` infers it as the set of
    /// bytes seen in the sample, which under-estimates it when the sample
    /// is small; pass the real alphabet (for example the 16 hex digits)
    /// when it is known.
    pub alphabet: Option<Vec<u8>>,
    /// Settings for the SP 800-22 / FIPS battery run on the concatenated
    /// bit stream; its `alpha` is also the significance level of the
    /// per-position tests.
    pub battery: battery::Options,
}

impl TokenOptions {
    /// Sets [`TokenOptions::alphabet`]. Duplicates are ignored.
    #[must_use]
    pub fn with_alphabet(mut self, alphabet: impl AsRef<[u8]>) -> Self {
        self.alphabet = Some(alphabet.as_ref().to_vec());
        self
    }

    /// Sets [`TokenOptions::battery`].
    #[must_use]
    pub const fn with_battery(mut self, battery: battery::Options) -> Self {
        self.battery = battery;
        self
    }
}

/// Character statistics at one position across all tokens long enough to
/// have it.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct PositionReport {
    /// Zero-based character position.
    pub position: usize,
    /// Number of tokens that have this position.
    pub samples: usize,
    /// Number of distinct symbols seen here.
    pub distinct: usize,
    /// Shannon entropy of the symbols seen here, in bits (at most
    /// `log₂ |alphabet|`). Estimated from the sample, so biased low for
    /// small samples.
    pub entropy_bits: f64,
    /// Pearson `χ²` of the symbol counts against the uniform distribution
    /// over the alphabet.
    pub chi_squared: f64,
    /// Upper-tail p-value of `chi_squared` with `|alphabet| − 1` degrees of
    /// freedom. The approximation needs about five expected occurrences per
    /// symbol (`samples ≥ 5 · |alphabet|`).
    pub p_value: f64,
}

/// Bias of one bit position across all tokens long enough to have it.
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct BitPositionReport {
    /// Zero-based bit position within the encoded token.
    pub position: usize,
    /// Number of tokens that have this bit.
    pub samples: usize,
    /// Number of those tokens in which it is set.
    pub ones: usize,
    /// Two-sided frequency-test p-value for `ones` against `samples / 2`.
    pub p_value: f64,
}

/// Results of [`analyze_tokens`].
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct TokenReport {
    /// Number of tokens analysed.
    pub tokens: usize,
    /// The alphabet, sorted and without duplicates.
    pub alphabet: Vec<u8>,
    /// Bits used to encode one symbol, `⌈log₂ |alphabet|⌉`.
    pub bits_per_symbol: u32,
    /// Significance level of the per-position verdicts.
    pub alpha: f64,
    /// Per-character-position statistics.
    pub positions: Vec<PositionReport>,
    /// Per-bit-position statistics.
    pub bit_positions: Vec<BitPositionReport>,
    /// Sum of the per-position entropies: an upper bound, in bits, on the
    /// entropy of a token, since correlations between positions are not
    /// subtracted.
    pub estimated_entropy_bits: f64,
    /// The SP 800-22 / FIPS battery run on all tokens' bits concatenated.
    pub battery: Report,
}

impl TokenReport {
    /// Character positions whose distribution departs from uniform at
    /// [`TokenReport::alpha`].
    pub fn biased_positions(&self) -> impl Iterator<Item = &PositionReport> {
        self.positions.iter().filter(|p| p.p_value < self.alpha)
    }

    /// Bit positions that are biased towards 0 or 1 at
    /// [`TokenReport::alpha`].
    pub fn biased_bit_positions(&self) -> impl Iterator<Item = &BitPositionReport> {
        self.bit_positions.iter().filter(|p| p.p_value < self.alpha)
    }

    /// Whether no position is biased and the battery passed.
    ///
    /// With many positions some will fall below `alpha` by chance (about
    /// `alpha` of them); callers that want a family-wise error rate should
    /// apply their own correction to the individual p-values.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.biased_positions().next().is_none()
            && self.biased_bit_positions().next().is_none()
            && self.battery.passed()
    }
}

/// Maps bytes to their index in a sorted alphabet.
struct SymbolIndex {
    alphabet: Vec<u8>,
    index: [Option<u8>; 256],
    bits_per_symbol: u32,
}

impl SymbolIndex {
    fn new<T: AsRef<[u8]>>(tokens: &[T], alphabet: Option<&[u8]>) -> Result<Self, Error> {
        let mut present = [false; 256];
        match alphabet {
            Some(alphabet) => alphabet
                .iter()
                .for_each(|&b| present[usize::from(b)] = true),
            None => tokens
                .iter()
                .flat_map(AsRef::as_ref)
                .for_each(|&b| present[usize::from(b)] = true),
        }
        let alphabet: Vec<u8> = (0..=255u8).filter(|&b| present[usize::from(b)]).collect();
        if alphabet.len() < 2 {
            return Err(Error::InvalidParameter {
                name: "alphabet",
                reason: "needs at least two distinct symbols",
            });
        }
        let mut index = [None; 256];
        for (i, &b) in (0u8..=255).zip(&alphabet) {
            index[usize::from(b)] = Some(i);
        }
        let bits_per_symbol = usize::BITS - (alphabet.len() - 1).leading_zeros();
        Ok(Self {
            alphabet,
            index,
            bits_per_symbol,
        })
    }

    fn lookup(&self, token: usize, offset: usize, byte: u8) -> Result<u8, Error> {
        self.index[usize::from(byte)].ok_or(Error::NotInAlphabet {
            token,
            offset,
            byte,
        })
    }
}

/// Encodes every token as the concatenation of its symbols' indices in the
/// (sorted) alphabet, `⌈log₂ |alphabet|⌉` bits each, most significant bit
/// first, and concatenates the tokens.
///
/// Unless the alphabet size is a power of two, the high bit of each symbol
/// is set less often than not, so the bit-level tests will flag the encoding
/// itself; prefer power-of-two alphabets (hex, base64) for bit-level work.
///
/// # Errors
///
/// [`Error::NotInAlphabet`] for a byte outside `alphabet`, and
/// [`Error::InvalidParameter`] for an alphabet of fewer than two symbols.
///
/// ```
/// use rune_randomness::{Bits, token_bits};
///
/// let bits = token_bits(&["0f", "a1"], b"0123456789abcdef")?;
/// assert_eq!(bits, Bits::parse("0000 1111 1010 0001")?);
/// # Ok::<(), rune_randomness::Error>(())
/// ```
pub fn token_bits<T: AsRef<[u8]>>(tokens: &[T], alphabet: &[u8]) -> Result<Bits, Error> {
    let symbols = SymbolIndex::new(tokens, Some(alphabet))?;
    encode(tokens, &symbols).map(|(bits, _)| bits)
}

/// Encodes the tokens and returns the stream plus each token's bits.
fn encode<T: AsRef<[u8]>>(tokens: &[T], symbols: &SymbolIndex) -> Result<(Bits, Vec<Bits>), Error> {
    let mut stream = Bits::new();
    let mut per_token = Vec::with_capacity(tokens.len());
    for (token, bytes) in tokens.iter().enumerate() {
        let mut bits = Bits::new();
        for (offset, &byte) in bytes.as_ref().iter().enumerate() {
            let symbol = symbols.lookup(token, offset, byte)?;
            bits.push_bits(u64::from(symbol), symbols.bits_per_symbol);
        }
        stream.extend(bits.iter().copied());
        per_token.push(bits);
    }
    Ok((stream, per_token))
}

/// Analyses a sample of tokens: per-position character distributions,
/// per-bit bias, and the SP 800-22 / FIPS battery on the concatenated bits
/// (see [`token_bits`] for the encoding).
///
/// Tokens may differ in length; each position is analysed over the tokens
/// that have it.
///
/// # Errors
///
/// [`Error::NoTokens`] for an empty sample, [`Error::NotInAlphabet`] for a
/// byte outside the configured alphabet, and [`Error::InvalidParameter`] for
/// an alphabet of fewer than two symbols or invalid battery options.
///
/// ```
/// use rune_randomness::{TokenOptions, analyze_tokens};
///
/// // Hex tokens whose first character is always '0'.
/// let tokens: Vec<String> = (0u32..400)
///     .map(|i| format!("0{:07x}", i.wrapping_mul(2_654_435_761) >> 4))
///     .collect();
/// let options = TokenOptions::default().with_alphabet("0123456789abcdef");
/// let report = analyze_tokens(&tokens, &options)?;
/// assert_eq!(report.bits_per_symbol, 4);
/// assert_eq!(report.biased_positions().next().map(|p| p.position), Some(0));
/// assert_eq!(report.positions[0].entropy_bits, 0.0);
/// # Ok::<(), rune_randomness::Error>(())
/// ```
pub fn analyze_tokens<T: AsRef<[u8]>>(
    tokens: &[T],
    options: &TokenOptions,
) -> Result<TokenReport, Error> {
    if tokens.is_empty() {
        return Err(Error::NoTokens);
    }
    let symbols = SymbolIndex::new(tokens, options.alphabet.as_deref())?;
    let (stream, per_token) = encode(tokens, &symbols)?;
    let battery = battery::run(&stream, &options.battery)?;

    let alphabet_size = symbols.alphabet.len();
    let max_len = tokens.iter().map(|t| t.as_ref().len()).max().unwrap_or(0);
    let mut positions = Vec::with_capacity(max_len);
    let mut column = Vec::with_capacity(tokens.len());
    let mut counts = vec![0usize; alphabet_size];
    for position in 0..max_len {
        column.clear();
        counts.fill(0);
        for token in tokens {
            if let Some(&byte) = token.as_ref().get(position) {
                column.push(byte);
                if let Some(i) = symbols.index[usize::from(byte)] {
                    counts[usize::from(i)] += 1;
                }
            }
        }
        let expected = to_f64(column.len()) / to_f64(alphabet_size);
        let chi_squared: f64 = counts
            .iter()
            .map(|&count| {
                let diff = to_f64(count) - expected;
                diff * diff / expected
            })
            .sum();
        positions.push(PositionReport {
            position,
            samples: column.len(),
            distinct: counts.iter().filter(|&&c| c > 0).count(),
            entropy_bits: rune_entropy::entropy(&column),
            chi_squared,
            p_value: chi_squared_sf(chi_squared, to_f64(alphabet_size - 1)),
        });
    }

    let max_bits = per_token.iter().map(|b| b.len()).max().unwrap_or(0);
    let bit_positions = (0..max_bits)
        .map(|position| {
            let (samples, ones) = per_token
                .iter()
                .filter_map(|bits| bits.get(position))
                .fold((0usize, 0usize), |(s, o), &bit| {
                    (s + 1, o + usize::from(bit))
                });
            let excess = (2.0f64.mul_add(to_f64(ones), -to_f64(samples))).abs();
            BitPositionReport {
                position,
                samples,
                ones,
                p_value: erfc(excess / (2.0 * to_f64(samples)).sqrt()),
            }
        })
        .collect();

    Ok(TokenReport {
        tokens: tokens.len(),
        estimated_entropy_bits: positions.iter().map(|p| p.entropy_bits).sum(),
        alphabet: symbols.alphabet,
        bits_per_symbol: symbols.bits_per_symbol,
        alpha: options.battery.alpha,
        positions,
        bit_positions,
        battery,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_degenerate_samples() {
        let none: [&str; 0] = [];
        assert_eq!(
            analyze_tokens(&none, &TokenOptions::default()),
            Err(Error::NoTokens)
        );
        assert!(matches!(
            analyze_tokens(&["aaa", "aa"], &TokenOptions::default()),
            Err(Error::InvalidParameter {
                name: "alphabet",
                ..
            })
        ));
        assert_eq!(
            analyze_tokens(&["ab", "xz"], &TokenOptions::default().with_alphabet("abz")),
            Err(Error::NotInAlphabet {
                token: 1,
                offset: 0,
                byte: b'x'
            })
        );
    }

    #[test]
    fn bits_per_symbol() {
        for (size, bits) in [
            (2usize, 1u32),
            (3, 2),
            (4, 2),
            (16, 4),
            (17, 5),
            (64, 6),
            (256, 8),
        ] {
            let alphabet: Vec<u8> = (0..=255u8).take(size).collect();
            let index =
                SymbolIndex::new(&[[0u8]], Some(&alphabet)).unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(index.bits_per_symbol, bits, "alphabet of {size}");
        }
    }

    #[test]
    fn varying_lengths() {
        let report = analyze_tokens(&["ab", "b", "abab"], &TokenOptions::default())
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(report.alphabet, b"ab");
        assert_eq!(report.positions.len(), 4);
        assert_eq!(report.positions[0].samples, 3);
        assert_eq!(report.positions[3].samples, 1);
        assert_eq!(report.bit_positions[1].samples, 2);
        assert_eq!(report.bit_positions[1].ones, 2);
    }
}

/// Xorshift64 PRNG — deterministic, no external dependencies.
pub struct Rng(u64);

impl Rng {
    pub(crate) const fn new(seed: u64) -> Self {
        let seed = if seed == 0 {
            0x6c62_272e_07bb_0142
        } else {
            seed
        };
        Self(seed)
    }

    const fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    #[allow(
        clippy::cast_precision_loss,
        reason = "counts and indices stay far below 2^52, so the f64 conversion is exact"
    )]
    pub(crate) fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    #[allow(
        clippy::cast_possible_truncation,
        reason = "the value is non-negative and bounded by the input size; float-to-int `as` saturates"
    )]
    pub(crate) const fn next_usize(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }
}

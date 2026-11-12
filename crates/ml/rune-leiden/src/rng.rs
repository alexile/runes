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
        clippy::cast_possible_truncation,
        reason = "the value is non-negative and bounded by the input size; float-to-int `as` saturates"
    )]
    pub(crate) const fn next_usize(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }

    /// Shuffles a slice in-place using Fisher–Yates.
    pub(crate) fn shuffle<T>(&mut self, slice: &mut [T]) {
        for i in (1..slice.len()).rev() {
            let j = self.next_usize(i + 1);
            slice.swap(i, j);
        }
    }
}

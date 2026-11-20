use rune_chain_core::tool;

struct Service;

impl Service {
    /// Look something up.
    #[tool]
    fn lookup(&self, key: String) -> String {
        key
    }
}

fn main() {}

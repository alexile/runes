use rune_chain_core::tool;

/// Generic.
#[tool]
fn echo<T: serde::Serialize>(value: T) -> T {
    value
}

fn main() {}

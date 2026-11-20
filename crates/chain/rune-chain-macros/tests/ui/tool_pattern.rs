use rune_chain_core::tool;

/// Add a pair.
#[tool]
fn add((a, b): (i32, i32)) -> i32 {
    a + b
}

fn main() {}

use rune_chain_core::tool;

/// Nested borrow.
#[tool]
fn greet(name: Option<&str>) -> String {
    name.unwrap_or("you").to_owned()
}

fn main() {}

use rune_chain_core::tool;

/// Unknown options.
#[tool(title = "x")]
fn a(x: i32) -> i32 {
    x
}

/// Unknown arg option.
#[tool]
fn b(#[arg(required)] x: i32) -> i32 {
    x
}

fn main() {}

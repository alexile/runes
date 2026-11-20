use rune_chain_core::tool;

/// Has a bad name.
#[tool(name = "get weather")]
fn get_weather(city: String) -> String {
    city
}

fn main() {}

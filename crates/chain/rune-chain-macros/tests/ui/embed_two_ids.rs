use rune_chain_embed::Embed;

#[derive(Embed)]
struct Doc {
    #[embed_id]
    a: u32,
    #[embed_id]
    b: u32,
    #[embed]
    text: String,
}

#[derive(Embed)]
struct Opts {
    #[embed(weight = 2)]
    text: String,
}

fn main() {}

//! Where the generated code finds the runtime crates.

use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::Ident;

/// Path to a runtime crate.
///
/// In order: a direct dependency on `package` (renamed or not), then the
/// `rune-chain` facade, which glob re-exports `rune_chain_core` at its root
/// and has `rune_chain_embed` as its `embed` module, and finally `::<lib>`
/// as written.
///
/// A crate expanding the macro on itself gets `::<lib>`, which works because
/// the runtime crates declare `extern crate self as <lib>;` (that also keeps
/// their doctests working).
fn resolve(package: &str, lib: &str, facade_module: Option<&str>) -> TokenStream {
    let lib = Ident::new(lib, Span::call_site());
    match crate_name(package) {
        Ok(FoundCrate::Name(name)) => {
            let name = Ident::new(&name, Span::call_site());
            return quote!(::#name);
        }
        Ok(FoundCrate::Itself) => return quote!(::#lib),
        Err(_) => {}
    }
    let facade = match crate_name("rune-chain") {
        Ok(FoundCrate::Name(name)) => Ident::new(&name, Span::call_site()),
        Ok(FoundCrate::Itself) => Ident::new("rune_chain", Span::call_site()),
        Err(_) => return quote!(::#lib),
    };
    let module = facade_module.map(|m| Ident::new(m, Span::call_site()));
    let module = module.iter();
    quote!(::#facade #(::#module)*)
}

/// Path to `rune_chain_core`, or the user's `crate = "..."` override.
pub fn core(custom: Option<&syn::Path>) -> TokenStream {
    custom.map_or_else(
        || resolve("rune-chain-core", "rune_chain_core", None),
        |p| quote!(#p),
    )
}

/// Path to `rune_chain_embed`, or the user's `crate = "..."` override.
pub fn embed(custom: Option<&syn::Path>) -> TokenStream {
    custom.map_or_else(
        || resolve("rune-chain-embed", "rune_chain_embed", Some("embed")),
        |p| quote!(#p),
    )
}

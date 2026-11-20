//! `#[derive(Embed)]`: the fields marked `#[embed]` are the texts to embed.

use proc_macro2::TokenStream;
use quote::{quote, quote_spanned};
use syn::spanned::Spanned;
use syn::{Data, DeriveInput, LitStr, Member};

use crate::paths;

pub fn expand(input: &DeriveInput) -> syn::Result<TokenStream> {
    let mut krate = None;
    for attr in &input.attrs {
        if !attr.path().is_ident("embed") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("crate") {
                let lit: LitStr = meta.value()?.parse()?;
                krate = Some(lit.parse::<syn::Path>()?);
                Ok(())
            } else {
                Err(meta.error("unknown #[embed] option on a struct; expected `crate`"))
            }
        })?;
    }

    let Data::Struct(data) = &input.data else {
        return Err(syn::Error::new(
            input.ident.span(),
            "#[derive(Embed)] works on structs only",
        ));
    };

    let mut texts = Vec::new();
    let mut id: Option<Member> = None;
    for (index, field) in data.fields.iter().enumerate() {
        let member = field
            .ident
            .clone()
            .map_or_else(|| Member::from(index), Member::Named);
        for attr in &field.attrs {
            if attr.path().is_ident("embed") {
                attr.meta.require_path_only().map_err(|_| {
                    syn::Error::new(attr.span(), "#[embed] on a field takes no options")
                })?;
                texts.push((member.clone(), field.ty.span()));
            } else if attr.path().is_ident("embed_id") {
                attr.meta.require_path_only()?;
                if id.is_some() {
                    return Err(syn::Error::new(
                        attr.span(),
                        "only one field can be #[embed_id]",
                    ));
                }
                id = Some(member.clone());
            }
        }
    }
    if texts.is_empty() {
        return Err(syn::Error::new(
            input.ident.span(),
            "#[derive(Embed)] needs at least one field marked #[embed]",
        ));
    }

    let embed = paths::embed(krate.as_ref());
    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let pushes = texts.iter().map(|(member, span)| {
        quote_spanned! {*span=>
            #embed::EmbedText::push_texts(&self.#member, out);
        }
    });
    let id_fn = id.map(|member| {
        quote! {
            fn embed_id(&self) -> ::core::option::Option<::std::string::String> {
                ::core::option::Option::Some(::std::string::ToString::to_string(&self.#member))
            }
        }
    });

    Ok(quote! {
        #[automatically_derived]
        impl #impl_generics #embed::Embed for #name #ty_generics #where_clause {
            fn embed_texts<'__rune_a>(
                &'__rune_a self,
                out: &mut ::std::vec::Vec<&'__rune_a str>,
            ) {
                #(#pushes)*
            }

            #id_fn
        }
    })
}

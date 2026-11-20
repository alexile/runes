//! Documents that know which of their texts to embed.

use std::borrow::Cow;
use std::rc::Rc;
use std::sync::Arc;

/// A document with one or more texts to embed.
///
/// Usually derived: with the `derive` feature, `#[derive(Embed)]` and
/// `#[embed]` on the text fields (and optionally `#[embed_id]` on an id
/// field) write this impl for you.
///
/// # Example
///
/// ```
/// use rune_chain_embed::{Embed, EmbedText};
///
/// struct Faq { question: String, answers: Vec<String> }
///
/// impl Embed for Faq {
///     fn embed_texts<'a>(&'a self, out: &mut Vec<&'a str>) {
///         self.question.push_texts(out);
///         self.answers.push_texts(out);
///     }
/// }
///
/// let faq = Faq { question: "Why Rust?".into(), answers: vec!["Speed.".into(), "Safety.".into()] };
/// assert_eq!(faq.texts(), ["Why Rust?", "Speed.", "Safety."]);
/// ```
pub trait Embed {
    /// Push the texts to embed onto `out`, in a stable order.
    fn embed_texts<'a>(&'a self, out: &mut Vec<&'a str>);

    /// A stable id for this document, used as the vector store record id.
    /// `None` (the default) means "derive one from the content".
    fn embed_id(&self) -> Option<String> {
        None
    }

    /// The texts to embed, collected into a new `Vec`.
    fn texts(&self) -> Vec<&str> {
        let mut out = Vec::new();
        self.embed_texts(&mut out);
        out
    }
}

impl Embed for str {
    fn embed_texts<'a>(&'a self, out: &mut Vec<&'a str>) {
        out.push(self);
    }
}

impl Embed for String {
    fn embed_texts<'a>(&'a self, out: &mut Vec<&'a str>) {
        out.push(self);
    }
}

impl<T: Embed + ?Sized> Embed for &T {
    fn embed_texts<'a>(&'a self, out: &mut Vec<&'a str>) {
        (**self).embed_texts(out);
    }

    fn embed_id(&self) -> Option<String> {
        (**self).embed_id()
    }
}

/// A field type `#[embed]` accepts: something holding zero or more texts.
///
/// Implemented for `str`, `String`, `Cow<str>`, `Box`, `Rc` and `Arc` of
/// those, references, `Option`, `Vec`, slices and arrays. Implement it for
/// your own field types to make them embeddable.
pub trait EmbedText {
    /// Push this value's texts onto `out`.
    fn push_texts<'a>(&'a self, out: &mut Vec<&'a str>);
}

impl EmbedText for str {
    fn push_texts<'a>(&'a self, out: &mut Vec<&'a str>) {
        out.push(self);
    }
}

impl EmbedText for String {
    fn push_texts<'a>(&'a self, out: &mut Vec<&'a str>) {
        out.push(self);
    }
}

impl EmbedText for Cow<'_, str> {
    fn push_texts<'a>(&'a self, out: &mut Vec<&'a str>) {
        out.push(self);
    }
}

macro_rules! forward_embed_text {
    ($($ty:ty),*) => {$(
        impl<T: EmbedText + ?Sized> EmbedText for $ty {
            fn push_texts<'a>(&'a self, out: &mut Vec<&'a str>) {
                (**self).push_texts(out);
            }
        }
    )*};
}

forward_embed_text!(&T, Box<T>, Rc<T>, Arc<T>);

impl<T: EmbedText> EmbedText for Option<T> {
    fn push_texts<'a>(&'a self, out: &mut Vec<&'a str>) {
        if let Some(v) = self {
            v.push_texts(out);
        }
    }
}

impl<T: EmbedText> EmbedText for [T] {
    fn push_texts<'a>(&'a self, out: &mut Vec<&'a str>) {
        for v in self {
            v.push_texts(out);
        }
    }
}

impl<T: EmbedText, const N: usize> EmbedText for [T; N] {
    fn push_texts<'a>(&'a self, out: &mut Vec<&'a str>) {
        self.as_slice().push_texts(out);
    }
}

impl<T: EmbedText> EmbedText for Vec<T> {
    fn push_texts<'a>(&'a self, out: &mut Vec<&'a str>) {
        self.as_slice().push_texts(out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Doc {
        title: &'static str,
        tags: Vec<Option<Box<str>>>,
        notes: [Cow<'static, str>; 2],
    }

    impl Embed for Doc {
        fn embed_texts<'a>(&'a self, out: &mut Vec<&'a str>) {
            self.title.push_texts(out);
            self.tags.push_texts(out);
            self.notes.push_texts(out);
        }
    }

    #[test]
    fn collects_in_field_order() {
        let d = Doc {
            title: "t",
            tags: vec![Some("a".into()), None, Some("b".into())],
            notes: [Cow::Borrowed("n1"), Cow::Owned("n2".into())],
        };
        assert_eq!(d.texts(), ["t", "a", "b", "n1", "n2"]);
        assert_eq!(d.embed_id(), None);
        assert_eq!("x".texts(), ["x"]);
        assert_eq!(String::from("y").texts(), ["y"]);
    }
}

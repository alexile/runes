//! Cleaning of `application/x-www-form-urlencoded` text (query strings and
//! form bodies).

use std::borrow::Cow;

/// Cleans each name and value with `clean(path, is_key, text)`, where `path`
/// is the single decoded name.
///
/// Splitting and decoding go through `form_urlencoded`, the code axum's
/// `Query` and `Form` extractors use, so the strings cleaned here are the
/// strings handlers see. Pairs that don't change keep their original bytes.
pub fn clean<F>(input: &str, mut clean: F) -> Cow<'_, str>
where
    F: for<'s> FnMut(&[String], bool, &'s str) -> Cow<'s, str>,
{
    let mut out: Option<String> = None;
    let mut copied = 0;
    let mut start = 0;

    for piece in input.split('&') {
        let piece_start = start;
        start += piece.len() + 1;
        let Some((name, value)) = form_urlencoded::parse(piece.as_bytes()).next() else {
            continue;
        };
        let path = [name.clone().into_owned()];
        let clean_name = clean(&path, true, &name);
        let clean_value = clean(&path, false, &value);
        if matches!(clean_name, Cow::Borrowed(_)) && matches!(clean_value, Cow::Borrowed(_)) {
            continue;
        }
        let out = out.get_or_insert_with(|| String::with_capacity(input.len()));
        out.push_str(&input[copied..piece_start]);
        out.extend(form_urlencoded::byte_serialize(clean_name.as_bytes()));
        out.push('=');
        out.extend(form_urlencoded::byte_serialize(clean_value.as_bytes()));
        copied = piece_start + piece.len();
    }

    out.map_or(Cow::Borrowed(input), |mut out| {
        out.push_str(&input[copied..]);
        Cow::Owned(out)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strip_x(input: &str) -> Cow<'_, str> {
        clean(input, |_, _, text| {
            if text.contains('x') {
                Cow::Owned(text.replace('x', ""))
            } else {
                Cow::Borrowed(text)
            }
        })
    }

    #[test]
    fn untouched_pairs_keep_their_encoding() {
        assert_eq!(strip_x("a=%41&&b=c+d&flag"), "a=%41&&b=c+d&flag");
        assert!(matches!(strip_x("a=1"), Cow::Borrowed(_)));
    }

    #[test]
    fn changed_pairs_are_reencoded() {
        assert_eq!(strip_x("a=%78y%20z&b=1"), "a=y+z&b=1");
        assert_eq!(strip_x("x%26=1&b=%2B"), "%26=1&b=%2B");
        assert_eq!(strip_x("q=x"), "q=");
    }
}

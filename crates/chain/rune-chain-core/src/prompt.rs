use std::collections::HashMap;

use serde_json::Value;

/// Key-value map of variables substituted into prompt templates.
///
/// Values are [`serde_json::Value`] so that booleans, numbers, lists, and
/// nested objects can be passed alongside plain strings.
pub type PromptArgs = HashMap<String, Value>;

/// Build a [`PromptArgs`] map from key-value pairs.
///
/// Keys are anything that implements `ToString`; values are passed through
/// [`serde_json::json!`] so any JSON-serialisable literal works.
///
/// # Example
///
/// ```rust
/// use rune_chain_core::prompt_args;
///
/// let args = prompt_args! {
///     "name" => "Alice",
///     "age"  => 30,
/// };
///
/// assert_eq!(args["name"], "Alice");
/// assert_eq!(args["age"], 30);
/// ```
#[macro_export]
macro_rules! prompt_args {
    ( $( $key:expr => $val:expr ),* $(,)? ) => {
        // Collect instead of inserting into a `let mut` map, so an empty
        // invocation does not trip `unused_mut` in the caller.
        <::std::collections::HashMap<String, ::serde_json::Value> as ::std::iter::FromIterator<_>>::from_iter([
            $( ($key.to_string(), ::serde_json::json!($val)) ),*
        ])
    };
}

#[cfg(test)]
mod tests {
    // `prompt_args!` expansions inside this crate are linted like caller
    // code; an empty invocation used to leave a needless `let mut`.
    #![deny(unused_mut)]

    use super::PromptArgs;

    #[test]
    fn empty_invocation_has_no_unused_mut() {
        let braces: PromptArgs = prompt_args! {};
        let comma: PromptArgs = prompt_args! {,};
        assert!(braces.is_empty() && comma.is_empty());
    }

    #[test]
    fn keys_accept_any_to_string() {
        let args = prompt_args! { 1 => true, 'c' => ::serde_json::Value::Null };
        assert_eq!(args["1"], true);
        assert!(args["c"].is_null());
    }
}

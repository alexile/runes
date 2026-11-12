use rune_chain_core::Message;

use crate::triple::Triple;

pub const SYSTEM_PROMPT: &str = "\
You are a knowledge extraction engine. Extract every factual relationship from the \
given text and return them as a JSON array.

Each element must be an object with exactly three string fields:
  \"subject\"  — the entity that has or performs the relationship
  \"relation\" — the relationship type (short verb phrase, snake_case preferred)
  \"object\"   — the entity that is the target of the relationship

Rules:
- Use consistent names for the same entity across all triples.
- Prefer specific relation labels over vague ones (e.g. \"founded\" not \"related_to\").
- If the text contains no relationships, return an empty array: []
- Output ONLY the JSON array. No markdown fences, no explanation, no other text.

Example output:
[
  {\"subject\": \"Marie Curie\", \"relation\": \"discovered\", \"object\": \"Polonium\"},
  {\"subject\": \"Marie Curie\", \"relation\": \"born_in\", \"object\": \"Warsaw\"},
  {\"subject\": \"Polonium\", \"relation\": \"named_after\", \"object\": \"Poland\"}
]";

pub fn build_messages(text: &str) -> Vec<Message> {
    vec![Message::system(SYSTEM_PROMPT), Message::human(text)]
}

/// Parse a JSON array of triples from LLM output.
///
/// Tolerates LLM output that wraps the array in markdown code fences or
/// includes a short preamble before the `[`. Returns only valid triples
/// (all three fields non-empty).
pub fn parse_triples(raw: &str) -> Vec<Triple> {
    let json = extract_json_array(raw);

    let Ok(value) = serde_json::from_str::<serde_json::Value>(json) else {
        return Vec::new();
    };

    let Some(array) = value.as_array() else {
        return Vec::new();
    };

    array
        .iter()
        .filter_map(|item| {
            let obj = item.as_object()?;
            let subject = obj.get("subject")?.as_str()?.to_string();
            let relation = obj.get("relation")?.as_str()?.to_string();
            let object = obj.get("object")?.as_str()?.to_string();
            let triple = Triple::new(subject, relation, object);
            triple.is_valid().then_some(triple)
        })
        .collect()
}

/// Find the first `[…]` span in `text`, tolerating markdown fences and
/// prose preambles that some LLMs emit before the actual JSON.
fn extract_json_array(text: &str) -> &str {
    let Some(start) = text.find('[') else {
        return text;
    };
    let end = match text[start..].rfind(']') {
        Some(i) => start + i + 1,
        None => return text,
    };
    &text[start..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_clean_json() {
        let raw = r#"[{"subject":"Alice","relation":"knows","object":"Bob"}]"#;
        let triples = parse_triples(raw);
        assert_eq!(triples.len(), 1);
        assert_eq!(triples[0].subject(), "Alice");
        assert_eq!(triples[0].relation(), "knows");
        assert_eq!(triples[0].object(), "Bob");
    }

    #[test]
    fn tolerates_markdown_fences() {
        let raw = "```json\n[{\"subject\":\"X\",\"relation\":\"r\",\"object\":\"Y\"}]\n```";
        let triples = parse_triples(raw);
        assert_eq!(triples.len(), 1);
    }

    #[test]
    fn tolerates_prose_preamble() {
        let raw =
            "Here are the triples:\n[{\"subject\":\"A\",\"relation\":\"b\",\"object\":\"C\"}]";
        let triples = parse_triples(raw);
        assert_eq!(triples.len(), 1);
    }

    #[test]
    fn skips_incomplete_triples() {
        let raw = r#"[{"subject":"","relation":"r","object":"Y"},{"subject":"A","relation":"r","object":"B"}]"#;
        let triples = parse_triples(raw);
        assert_eq!(triples.len(), 1);
        assert_eq!(triples[0].subject(), "A");
    }

    #[test]
    fn empty_array_returns_empty_vec() {
        assert_eq!(parse_triples("[]"), [] as [Triple; 0]);
    }

    #[test]
    fn garbage_input_returns_empty_vec() {
        assert_eq!(parse_triples("sorry i cannot help"), [] as [Triple; 0]);
    }
}

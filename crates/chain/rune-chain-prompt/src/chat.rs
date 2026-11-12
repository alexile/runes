use rune_chain_core::{ChainError, Message, PromptArgs, Role};
use serde_json::Value;

use crate::error::TemplateError;
use crate::template::{PromptTemplate, StringTemplate, check_declared, legacy_error, push_unique};

/// A single-role message template: one [`Role`] paired with a [`StringTemplate`].
///
/// # Example
///
/// ```rust
/// use rune_chain_prompt::MessageTemplate;
/// use rune_chain_core::{Role, prompt_args};
///
/// let tmpl = MessageTemplate::human("Tell me about {topic}.");
/// let msg = tmpl.format(&prompt_args! { "topic" => "Rust" }).unwrap();
/// assert_eq!(msg.content, "Tell me about Rust.");
/// ```
#[derive(Debug, Clone)]
pub struct MessageTemplate {
    role: Role,
    template: StringTemplate,
}

impl MessageTemplate {
    /// Create a message template with an explicit role and template string.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_prompt::MessageTemplate;
    /// use rune_chain_core::{Role, PromptArgs};
    ///
    /// let tmpl = MessageTemplate::new(Role::System, "You are a {persona} assistant.");
    /// let msg = tmpl.format(&PromptArgs::new()).unwrap_or_else(|_| {
    ///     // MissingVariable: persona
    ///     use rune_chain_core::Message;
    ///     Message::system("fallback")
    /// });
    /// ```
    pub fn new(role: Role, template: impl Into<String>) -> Self {
        Self {
            role,
            template: StringTemplate::new(template),
        }
    }

    /// System-role message template.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_prompt::MessageTemplate;
    /// use rune_chain_core::{Role, PromptArgs};
    ///
    /// let tmpl = MessageTemplate::system("You are a helpful assistant.");
    /// let msg = tmpl.format(&PromptArgs::new()).unwrap();
    /// assert_eq!(msg.role, Role::System);
    /// ```
    pub fn system(template: impl Into<String>) -> Self {
        Self::new(Role::System, template)
    }

    /// Human-role message template.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_prompt::MessageTemplate;
    /// use rune_chain_core::{Role, prompt_args};
    ///
    /// let tmpl = MessageTemplate::human("What is {question}?");
    /// let msg = tmpl.format(&prompt_args! { "question" => "the answer to life" }).unwrap();
    /// assert_eq!(msg.role, Role::Human);
    /// ```
    pub fn human(template: impl Into<String>) -> Self {
        Self::new(Role::Human, template)
    }

    /// AI-role message template.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_prompt::MessageTemplate;
    /// use rune_chain_core::{Role, prompt_args};
    ///
    /// let tmpl = MessageTemplate::ai("The answer is {answer}.");
    /// let msg = tmpl.format(&prompt_args! { "answer" => "42" }).unwrap();
    /// assert_eq!(msg.role, Role::Ai);
    /// ```
    pub fn ai(template: impl Into<String>) -> Self {
        Self::new(Role::Ai, template)
    }

    /// Pair a role with a prepared [`StringTemplate`], keeping its partials,
    /// guards and length limit.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_prompt::{MessageTemplate, StringTemplate, ValueGuard};
    /// use rune_chain_core::{Role, prompt_args};
    ///
    /// let body = StringTemplate::try_new("Question: {q}")?.guard("q", ValueGuard::untrusted("q"));
    /// let tmpl = MessageTemplate::from_template(Role::Human, body);
    /// let msg = tmpl.format(&prompt_args! { "q" => "<hi>" }).unwrap();
    /// assert_eq!(msg.content, "Question: <q>&lt;hi&gt;</q>");
    /// # Ok::<(), rune_chain_prompt::TemplateError>(())
    /// ```
    #[must_use]
    pub const fn from_template(role: Role, template: StringTemplate) -> Self {
        Self { role, template }
    }

    /// The role of the produced message.
    #[must_use]
    pub const fn role(&self) -> &Role {
        &self.role
    }

    /// The underlying string template.
    #[must_use]
    pub const fn template(&self) -> &StringTemplate {
        &self.template
    }

    /// Format this template into a [`Message`], substituting all variables.
    pub fn format(&self, args: &PromptArgs) -> Result<Message, ChainError> {
        let content = self.template.format(args)?;
        Ok(Message::new(self.role.clone(), content))
    }

    /// Like [`format`](Self::format), but a missing-variable error lists
    /// every missing variable.
    pub fn try_format(&self, args: &PromptArgs) -> Result<Message, TemplateError> {
        let content = self.template.try_format(args)?;
        Ok(Message::new(self.role.clone(), content))
    }

    /// Names of variables this template requires.
    #[must_use]
    pub fn input_variables(&self) -> Vec<String> {
        self.template.input_variables()
    }
}

/// Inserts a list of [`Message`]s (typically conversation history) taken
/// from one variable into a [`ChatTemplate`] — the equivalent of
/// `LangChain`'s `MessagesPlaceholder`.
///
/// The variable's value must be a JSON array of serialised [`Message`]s
/// (build one with [`messages_value`]). Inserted messages are copied
/// verbatim: their content is never parsed as a template, so `{braces}` in
/// history are harmless.
///
/// # Example
///
/// ```rust
/// use rune_chain_prompt::{ChatTemplate, MessageTemplate, MessagesPlaceholder, messages_value};
/// use rune_chain_core::{Message, PromptArgs};
///
/// let tmpl = ChatTemplate::new(vec![MessageTemplate::system("Be brief.")])
///     .with_placeholder(MessagesPlaceholder::new("history").last(2))
///     .with_message(MessageTemplate::human("{input}"));
///
/// let history = [Message::human("hi"), Message::ai("hello {there}"), Message::human("2+2?"), Message::ai("4")];
/// let mut args = PromptArgs::new();
/// args.insert("history".into(), messages_value(&history));
/// args.insert("input".into(), "and 3+3?".into());
///
/// let msgs = tmpl.format_messages(&args).unwrap();
/// let texts: Vec<_> = msgs.iter().map(|m| m.content.to_string()).collect();
/// assert_eq!(texts, ["Be brief.", "2+2?", "4", "and 3+3?"]);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessagesPlaceholder {
    name: String,
    optional: bool,
    last: Option<usize>,
}

impl MessagesPlaceholder {
    /// A required placeholder reading the variable `name`.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            optional: false,
            last: None,
        }
    }

    /// Make the placeholder optional: a missing or `null` variable inserts
    /// nothing instead of failing, and the variable is not listed as an
    /// input variable.
    #[must_use]
    pub const fn optional(mut self) -> Self {
        self.optional = true;
        self
    }

    /// Insert only the last `n` messages (bounds history length).
    #[must_use]
    pub const fn last(mut self, n: usize) -> Self {
        self.last = Some(n);
        self
    }

    /// The variable this placeholder reads.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether the placeholder is optional.
    #[must_use]
    pub const fn is_optional(&self) -> bool {
        self.optional
    }

    fn resolve(&self, args: &PromptArgs) -> Result<Vec<Message>, TemplateError> {
        let value = match args.get(&self.name) {
            None | Some(Value::Null) if self.optional => return Ok(Vec::new()),
            None => return Err(TemplateError::MissingVariables(vec![self.name.clone()])),
            Some(v) => v,
        };
        let Value::Array(items) = value else {
            return Err(TemplateError::InvalidPlaceholderValue {
                name: self.name.clone(),
                reason: "expected a JSON array of messages".into(),
            });
        };
        let skip = self.last.map_or(0, |n| items.len().saturating_sub(n));
        items[skip..]
            .iter()
            .enumerate()
            .map(|(i, item)| {
                serde_json::from_value::<Message>(item.clone()).map_err(|e| {
                    TemplateError::InvalidPlaceholderValue {
                        name: self.name.clone(),
                        reason: format!("item {}: {e}", skip + i),
                    }
                })
            })
            .collect()
    }
}

/// Serialise messages into the [`Value`] a [`MessagesPlaceholder`] expects.
///
/// ```rust
/// use rune_chain_core::Message;
///
/// let v = rune_chain_prompt::messages_value(&[Message::human("hi")]);
/// assert!(v.is_array());
/// ```
#[must_use]
pub fn messages_value(messages: &[Message]) -> Value {
    // Serialising a `Message` cannot fail: it is plain data with string keys.
    Value::Array(
        messages
            .iter()
            .filter_map(|m| serde_json::to_value(m).ok())
            .collect(),
    )
}

/// One slot of a [`ChatTemplate`].
#[derive(Debug, Clone)]
pub enum ChatPart {
    /// A message rendered from a template.
    Message(MessageTemplate),
    /// Messages inserted from a variable.
    Placeholder(MessagesPlaceholder),
}

impl From<MessageTemplate> for ChatPart {
    fn from(m: MessageTemplate) -> Self {
        Self::Message(m)
    }
}

impl From<MessagesPlaceholder> for ChatPart {
    fn from(p: MessagesPlaceholder) -> Self {
        Self::Placeholder(p)
    }
}

/// A borrowed slot of a [`ChatTemplate`].
enum Slot<'a> {
    Message(&'a MessageTemplate),
    Placeholder(&'a MessagesPlaceholder),
}

/// An ordered list of [`MessageTemplate`]s (and optional
/// [`MessagesPlaceholder`]s) that formats into a conversation.
///
/// Each message template becomes one [`Message`] in the output, with its own
/// role and template string; each placeholder expands to the messages held
/// in its variable. All slots share the same [`PromptArgs`] map.
///
/// # Example
///
/// ```rust
/// use rune_chain_prompt::{ChatTemplate, MessageTemplate};
/// use rune_chain_core::{Role, prompt_args};
///
/// let tmpl = ChatTemplate::new(vec![
///     MessageTemplate::system("You are a helpful assistant."),
///     MessageTemplate::human("Tell me about {topic}."),
/// ]);
///
/// let messages = tmpl.format_messages(&prompt_args! { "topic" => "Rust" }).unwrap();
/// assert_eq!(messages.len(), 2);
/// assert_eq!(messages[0].role, Role::System);
/// assert_eq!(messages[1].content, "Tell me about Rust.");
/// ```
#[derive(Debug, Clone)]
pub struct ChatTemplate {
    templates: Vec<MessageTemplate>,
    /// `(index, placeholder)`: the placeholder goes before `templates[index]`
    /// (or at the end when `index == templates.len()`); sorted by index,
    /// stable for equal indices.
    placeholders: Vec<(usize, MessagesPlaceholder)>,
    max_len: Option<usize>,
}

impl ChatTemplate {
    /// Create a chat template from an ordered list of message templates.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_prompt::{ChatTemplate, MessageTemplate};
    ///
    /// let tmpl = ChatTemplate::new(vec![
    ///     MessageTemplate::system("Be concise."),
    ///     MessageTemplate::human("{question}"),
    /// ]);
    /// assert_eq!(tmpl.input_variables(), vec!["question"]);
    /// ```
    #[must_use]
    pub const fn new(templates: Vec<MessageTemplate>) -> Self {
        Self {
            templates,
            placeholders: Vec::new(),
            max_len: None,
        }
    }

    /// Create a chat template from message templates and placeholders.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_prompt::{ChatTemplate, MessageTemplate, MessagesPlaceholder};
    ///
    /// let tmpl = ChatTemplate::from_parts([
    ///     MessageTemplate::system("Be concise.").into(),
    ///     MessagesPlaceholder::new("history").into(),
    ///     MessageTemplate::human("{question}").into(),
    /// ]);
    /// assert_eq!(tmpl.input_variables(), ["history", "question"]);
    /// ```
    #[must_use]
    pub fn from_parts(parts: impl IntoIterator<Item = ChatPart>) -> Self {
        parts
            .into_iter()
            .fold(Self::new(Vec::new()), |acc, part| match part {
                ChatPart::Message(m) => acc.with_message(m),
                ChatPart::Placeholder(p) => acc.with_placeholder(p),
            })
    }

    /// Append a message template.
    #[must_use]
    pub fn with_message(mut self, template: MessageTemplate) -> Self {
        self.templates.push(template);
        self
    }

    /// Append a messages placeholder.
    #[must_use]
    pub fn with_placeholder(mut self, placeholder: MessagesPlaceholder) -> Self {
        self.placeholders.push((self.templates.len(), placeholder));
        self
    }

    /// Reject conversations whose total text exceeds `max` bytes with
    /// [`TemplateError::TooLong`] (inserted history included).
    #[must_use]
    pub const fn with_max_len(mut self, max: usize) -> Self {
        self.max_len = Some(max);
        self
    }

    /// The slots of this template, in order.
    #[must_use]
    pub fn parts(&self) -> Vec<ChatPart> {
        self.slots()
            .into_iter()
            .map(|slot| match slot {
                Slot::Message(m) => ChatPart::Message(m.clone()),
                Slot::Placeholder(p) => ChatPart::Placeholder(p.clone()),
            })
            .collect()
    }

    /// Every slot, in order.
    fn slots(&self) -> Vec<Slot<'_>> {
        let mut out = Vec::with_capacity(self.templates.len() + self.placeholders.len());
        let mut ph = self.placeholders.iter().peekable();
        for (i, t) in self.templates.iter().enumerate() {
            while let Some((_, p)) = ph.next_if(|(idx, _)| *idx <= i) {
                out.push(Slot::Placeholder(p));
            }
            out.push(Slot::Message(t));
        }
        out.extend(ph.map(|(_, p)| Slot::Placeholder(p)));
        out
    }

    /// Format every slot and return the complete conversation.
    ///
    /// All templates are formatted with the same `args` map. Returns an error
    /// on the first missing variable encountered.
    pub fn format_messages(&self, args: &PromptArgs) -> Result<Vec<Message>, ChainError> {
        let mut out = Vec::new();
        for slot in self.slots() {
            match slot {
                Slot::Message(m) => out.push(m.format(args)?),
                Slot::Placeholder(p) => out.extend(p.resolve(args).map_err(legacy_error)?),
            }
        }
        self.check_len(&out)?;
        Ok(out)
    }

    /// Like [`format_messages`](Self::format_messages), but a
    /// missing-variable error lists every missing variable of every slot.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_prompt::{ChatTemplate, MessageTemplate, TemplateError};
    /// use rune_chain_core::PromptArgs;
    ///
    /// let tmpl = ChatTemplate::new(vec![
    ///     MessageTemplate::system("{persona}"),
    ///     MessageTemplate::human("{question}"),
    /// ]);
    /// let err = tmpl.try_format_messages(&PromptArgs::new()).unwrap_err();
    /// assert_eq!(err, TemplateError::MissingVariables(vec!["persona".into(), "question".into()]));
    /// ```
    pub fn try_format_messages(&self, args: &PromptArgs) -> Result<Vec<Message>, TemplateError> {
        let missing = self.missing_variables(args);
        if !missing.is_empty() {
            return Err(TemplateError::MissingVariables(missing));
        }
        let mut out = Vec::new();
        for slot in self.slots() {
            match slot {
                Slot::Message(m) => out.push(m.try_format(args)?),
                Slot::Placeholder(p) => out.extend(p.resolve(args)?),
            }
        }
        self.check_len(&out)?;
        Ok(out)
    }

    fn check_len(&self, messages: &[Message]) -> Result<(), TemplateError> {
        let Some(max) = self.max_len else {
            return Ok(());
        };
        let len: usize = messages
            .iter()
            .map(|m| m.content.text_content().len())
            .sum();
        if len > max {
            Err(TemplateError::TooLong { len, max })
        } else {
            Ok(())
        }
    }

    /// The variables `args` does not supply, across all slots, in order of
    /// first appearance.
    #[must_use]
    pub fn missing_variables(&self, args: &PromptArgs) -> Vec<String> {
        let mut missing = Vec::new();
        for slot in self.slots() {
            match slot {
                Slot::Message(m) => {
                    for v in m.template().missing_variables(args) {
                        push_unique(&mut missing, &v);
                    }
                }
                Slot::Placeholder(p) => {
                    if !p.optional && !args.contains_key(&p.name) {
                        push_unique(&mut missing, &p.name);
                    }
                }
            }
        }
        missing
    }

    /// Check that the template uses exactly the `declared` input variables.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_prompt::{ChatTemplate, MessageTemplate};
    ///
    /// let tmpl = ChatTemplate::new(vec![MessageTemplate::human("{question}")]);
    /// assert!(tmpl.validate_input_variables(&["question"]).is_ok());
    /// assert!(tmpl.validate_input_variables(&["question", "extra"]).is_err());
    /// ```
    pub fn validate_input_variables<S: AsRef<str>>(
        &self,
        declared: &[S],
    ) -> Result<(), TemplateError> {
        check_declared(&self.input_variables(), declared)
    }

    /// Names of all variables used across all slots (deduplicated, ordered
    /// by first appearance). Required placeholders are included; optional
    /// ones and partials are not.
    #[must_use]
    pub fn input_variables(&self) -> Vec<String> {
        let mut vars: Vec<String> = Vec::new();
        for slot in self.slots() {
            match slot {
                Slot::Message(m) => {
                    for v in m.input_variables() {
                        push_unique(&mut vars, &v);
                    }
                }
                Slot::Placeholder(p) => {
                    if !p.optional {
                        push_unique(&mut vars, &p.name);
                    }
                }
            }
        }
        vars
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rune_chain_core::prompt_args;

    #[test]
    fn formats_single_message() {
        let tmpl = MessageTemplate::human("Tell me about {topic}.");
        let msg = tmpl.format(&prompt_args! { "topic" => "Rust" }).unwrap();
        assert_eq!(msg.role, Role::Human);
        assert_eq!(msg.content, "Tell me about Rust.");
    }

    #[test]
    fn chat_template_formats_all_messages() {
        let tmpl = ChatTemplate::new(vec![
            MessageTemplate::system("You are helpful."),
            MessageTemplate::human("Tell me about {topic}."),
        ]);
        let messages = tmpl
            .format_messages(&prompt_args! { "topic" => "Rust" })
            .unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].role, Role::System);
        assert_eq!(messages[1].content, "Tell me about Rust.");
    }

    #[test]
    fn chat_template_deduplicates_variables() {
        let tmpl = ChatTemplate::new(vec![
            MessageTemplate::human("Hello, {name}."),
            MessageTemplate::human("Your name is {name}, right?"),
            MessageTemplate::human("Topic: {topic}."),
        ]);
        let vars = tmpl.input_variables();
        assert_eq!(vars, vec!["name", "topic"]);
    }

    #[test]
    fn placeholder_positions_are_preserved() {
        let tmpl = ChatTemplate::from_parts([
            MessagesPlaceholder::new("a").into(),
            MessageTemplate::system("s").into(),
            MessagesPlaceholder::new("b").into(),
            MessagesPlaceholder::new("c").optional().into(),
            MessageTemplate::human("h").into(),
            MessagesPlaceholder::new("d").into(),
        ]);
        let names: Vec<String> = tmpl
            .parts()
            .into_iter()
            .map(|p| match p {
                ChatPart::Message(m) => m.template().template().to_owned(),
                ChatPart::Placeholder(p) => p.name().to_owned(),
            })
            .collect();
        assert_eq!(names, ["a", "s", "b", "c", "h", "d"]);
        assert_eq!(tmpl.input_variables(), ["a", "b", "d"]);
    }

    #[test]
    fn placeholder_inserts_history_verbatim() {
        let tmpl = ChatTemplate::new(vec![MessageTemplate::system("sys")])
            .with_placeholder(MessagesPlaceholder::new("history"))
            .with_message(MessageTemplate::human("{q}"));
        let mut args = prompt_args! { "q" => "now" };
        args.insert(
            "history".into(),
            messages_value(&[Message::human("{q}"), Message::ai("ok")]),
        );
        let msgs = tmpl.format_messages(&args).unwrap();
        assert_eq!(msgs.len(), 4);
        assert_eq!(msgs[1].content, "{q}");
        assert_eq!(msgs[2].role, Role::Ai);
        assert_eq!(msgs[3].content, "now");
    }

    #[test]
    fn optional_placeholder_accepts_missing_and_null() {
        let tmpl =
            ChatTemplate::new(vec![]).with_placeholder(MessagesPlaceholder::new("h").optional());
        assert_eq!(tmpl.format_messages(&PromptArgs::new()).unwrap().len(), 0);
        let args = PromptArgs::from([("h".to_string(), Value::Null)]);
        assert_eq!(tmpl.format_messages(&args).unwrap().len(), 0);
    }

    #[test]
    fn bad_placeholder_values_are_rejected() {
        let tmpl = ChatTemplate::new(vec![]).with_placeholder(MessagesPlaceholder::new("h"));
        assert!(matches!(
            tmpl.format_messages(&PromptArgs::new()),
            Err(ChainError::MissingVariable(v)) if v == "h"
        ));
        let args = PromptArgs::from([("h".to_string(), Value::from("text"))]);
        assert!(matches!(
            tmpl.format_messages(&args),
            Err(ChainError::ParseError(_))
        ));
        let args = PromptArgs::from([("h".to_string(), serde_json::json!([{"nope": 1}]))]);
        let err = tmpl.try_format_messages(&args).unwrap_err();
        assert!(err.to_string().contains("item 0"), "{err}");
    }

    #[test]
    fn chat_max_len_counts_history() {
        let tmpl = ChatTemplate::new(vec![MessageTemplate::human("abc")])
            .with_placeholder(MessagesPlaceholder::new("h"))
            .with_max_len(5);
        let args = PromptArgs::from([("h".to_string(), messages_value(&[Message::ai("xyz")]))]);
        assert_eq!(
            tmpl.try_format_messages(&args).unwrap_err(),
            TemplateError::TooLong { len: 6, max: 5 }
        );
    }

    #[test]
    fn try_format_lists_all_missing() {
        let tmpl = ChatTemplate::new(vec![
            MessageTemplate::system("{a}"),
            MessageTemplate::human("{b} {a}"),
        ])
        .with_placeholder(MessagesPlaceholder::new("h"));
        assert_eq!(
            tmpl.try_format_messages(&PromptArgs::new()).unwrap_err(),
            TemplateError::MissingVariables(vec!["a".into(), "b".into(), "h".into()])
        );
    }

    #[test]
    fn missing_variable_propagates() {
        let tmpl = ChatTemplate::new(vec![MessageTemplate::human("Hello, {name}.")]);
        assert!(tmpl.format_messages(&PromptArgs::new()).is_err());
    }
}

//! Graph state, partial updates and per-field reducers.

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::hash::{BuildHasher, Hash};

use rune_chain_core::Message;
use serde::Serialize;
use serde::de::DeserializeOwned;

/// The state a graph passes between nodes.
///
/// Nodes never return a whole state. They return an [`Update`](Self::Update),
/// a partial change that [`merge`](Self::merge) folds in, usually one
/// [`Reducer`] per field. The [`state!`](crate::state!) macro writes the
/// update type and `merge` for you.
///
/// Both types must serialize so runs can be checkpointed and resumed.
pub trait GraphState: Clone + Serialize + DeserializeOwned + Send + Sync + 'static {
    /// A partial update returned by nodes. `Default` must mean "no change".
    type Update: Clone + Default + Serialize + DeserializeOwned + Send + Sync + 'static;

    /// Fold `update` into `self`.
    fn merge(&mut self, update: Self::Update);
}

/// How one field folds in its part of an update.
///
/// Reducers are zero-sized marker types used through this trait, for example
/// `<Append as Reducer<Vec<String>>>::reduce(&mut notes, more)`.
pub trait Reducer<T> {
    /// What an update carries for the field.
    type Update;

    /// Fold `update` into `current`.
    fn reduce(current: &mut T, update: Self::Update);
}

/// Overwrite the field with the new value (`LangGraph`'s default channel).
#[derive(Debug, Clone, Copy, Default)]
pub struct Replace;

impl<T> Reducer<T> for Replace {
    type Update = T;

    fn reduce(current: &mut T, update: T) {
        *current = update;
    }
}

/// Append the new items to a `Vec` (`operator.add` on lists).
#[derive(Debug, Clone, Copy, Default)]
pub struct Append;

impl<T> Reducer<Vec<T>> for Append {
    type Update = Vec<T>;

    fn reduce(current: &mut Vec<T>, update: Vec<T>) {
        current.extend(update);
    }
}

/// Add the new value to a number (`operator.add` on numbers).
#[derive(Debug, Clone, Copy, Default)]
pub struct Sum;

impl<T: std::ops::AddAssign> Reducer<T> for Sum {
    type Update = T;

    fn reduce(current: &mut T, update: T) {
        *current += update;
    }
}

/// Insert the new entries into a map, overwriting existing keys.
#[derive(Debug, Clone, Copy, Default)]
pub struct MergeMap;

impl<K: Ord, V> Reducer<BTreeMap<K, V>> for MergeMap {
    type Update = BTreeMap<K, V>;

    fn reduce(current: &mut BTreeMap<K, V>, update: Self::Update) {
        current.extend(update);
    }
}

impl<K: Eq + Hash, V, H: BuildHasher> Reducer<HashMap<K, V, H>> for MergeMap {
    type Update = HashMap<K, V, H>;

    fn reduce(current: &mut HashMap<K, V, H>, update: Self::Update) {
        current.extend(update);
    }
}

/// A stable identity for a message, used by [`AddMessages`] to replace
/// instead of append.
pub trait MessageId {
    /// The id, or `None` for messages that are always appended.
    fn message_id(&self) -> Option<Cow<'_, str>>;
}

/// Core messages use their optional [`Message::id`]. Messages without one
/// are always appended.
impl MessageId for Message {
    fn message_id(&self) -> Option<Cow<'_, str>> {
        self.id.as_deref().map(Cow::Borrowed)
    }
}

/// Append messages, but replace one in place when a message with the same
/// [`MessageId`] is already there (`LangGraph`'s `add_messages`).
///
/// Give messages ids with [`Message::with_id`] to edit or replace them
/// later; messages without an id are always appended. Provider tool-call ids
/// are not used, because some models reuse them across turns.
#[derive(Debug, Clone, Copy, Default)]
pub struct AddMessages;

impl<M: MessageId> Reducer<Vec<M>> for AddMessages {
    type Update = Vec<M>;

    fn reduce(current: &mut Vec<M>, update: Vec<M>) {
        if update.iter().all(|m| m.message_id().is_none()) {
            current.extend(update);
            return;
        }
        let mut index: HashMap<String, usize> = current
            .iter()
            .enumerate()
            .filter_map(|(i, m)| m.message_id().map(|id| (id.into_owned(), i)))
            .collect();
        current.reserve(update.len());
        for message in update {
            let id = message.message_id().map(Cow::into_owned);
            match id {
                Some(id) => {
                    if let Some(&at) = index.get(&id) {
                        current[at] = message;
                    } else {
                        index.insert(id, current.len());
                        current.push(message);
                    }
                }
                None => current.push(message),
            }
        }
    }
}

/// A state with a message history, needed by [`LlmNode::new`](crate::LlmNode::new),
/// [`ToolNode`](crate::ToolNode) and the prebuilt agent.
pub trait HasMessages: GraphState {
    /// The conversation so far.
    fn messages(&self) -> &[Message];

    /// An update that adds `messages` to the history.
    fn messages_update(messages: Vec<Message>) -> Self::Update;
}

/// Declare a state struct together with its update type and reducers.
///
/// Each field names its [`Reducer`]. The macro emits the struct as written
/// (add your own derives, which must include `Clone`, `Serialize` and
/// `Deserialize`), an update struct whose fields are all `Option`s with a
/// builder method per field, and the [`GraphState`] impl. The update derives
/// `Debug`, `Clone`, `Default`, `Serialize` and `Deserialize` through
/// `::serde`, so your crate needs `serde` with the `derive` feature.
///
/// ```rust
/// use rune_chain_graph::{Append, GraphState, Replace, Sum, state};
/// use serde::{Deserialize, Serialize};
///
/// state! {
///     #[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
///     pub struct Research => ResearchUpdate {
///         pub topic: String = Replace,
///         pub notes: Vec<String> = Append,
///         pub calls: u32 = Sum,
///     }
/// }
///
/// let mut s = Research::default();
/// s.merge(ResearchUpdate::default().notes(vec!["a".into()]).calls(1));
/// s.merge(ResearchUpdate::default().notes(vec!["b".into()]).calls(2).topic("rust".into()));
/// assert_eq!(s.notes, ["a", "b"]);
/// assert_eq!(s.calls, 3);
/// assert_eq!(s.topic, "rust");
/// ```
#[macro_export]
macro_rules! state {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident => $update:ident {
            $( $(#[$fmeta:meta])* $fvis:vis $field:ident : $ty:ty = $reducer:ty ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        $vis struct $name {
            $( $(#[$fmeta])* $fvis $field: $ty, )*
        }

        #[doc = concat!("A partial update for [`", stringify!($name), "`]. `None` fields leave the state alone.")]
        #[derive(Debug, Clone, Default, ::serde::Serialize, ::serde::Deserialize)]
        #[serde(default)]
        $vis struct $update {
            $(
                #[doc = concat!("Change to `", stringify!($field), "`, folded in by `", stringify!($reducer), "`.")]
                #[serde(skip_serializing_if = "Option::is_none")]
                $fvis $field: ::core::option::Option<<$reducer as $crate::Reducer<$ty>>::Update>,
            )*
        }

        impl $update {
            $(
                #[doc = concat!("Set the change to `", stringify!($field), "`.")]
                #[must_use]
                #[allow(dead_code, clippy::missing_const_for_fn)]
                $fvis fn $field(mut self, value: <$reducer as $crate::Reducer<$ty>>::Update) -> Self {
                    self.$field = ::core::option::Option::Some(value);
                    self
                }
            )*
        }

        impl $crate::GraphState for $name {
            type Update = $update;

            fn merge(&mut self, update: $update) {
                $(
                    if let ::core::option::Option::Some(value) = update.$field {
                        <$reducer as $crate::Reducer<$ty>>::reduce(&mut self.$field, value);
                    }
                )*
            }
        }
    };
}

state! {
    /// The common chat state: a message list merged with [`AddMessages`]
    /// (`LangGraph`'s `MessagesState`).
    #[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    pub struct MessagesState => MessagesUpdate {
        /// The conversation.
        pub messages: Vec<Message> = AddMessages,
    }
}

impl MessagesState {
    /// A state holding `messages`.
    #[must_use]
    pub const fn new(messages: Vec<Message>) -> Self {
        Self { messages }
    }

    /// The text of the last message, or `""`.
    #[must_use]
    pub fn last_text(&self) -> String {
        self.messages.last().map(Message::text).unwrap_or_default()
    }
}

impl MessagesUpdate {
    /// An update adding `messages`.
    #[must_use]
    pub const fn new(messages: Vec<Message>) -> Self {
        Self {
            messages: Some(messages),
        }
    }
}

impl HasMessages for MessagesState {
    fn messages(&self) -> &[Message] {
        &self.messages
    }

    fn messages_update(messages: Vec<Message>) -> MessagesUpdate {
        MessagesUpdate::new(messages)
    }
}

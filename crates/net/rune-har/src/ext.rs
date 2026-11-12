//! Names of the custom (`_`-prefixed) fields this crate reads and writes.
//!
//! HAR 1.2 reserves names starting with `_` for custom fields. These carry
//! the parts of an [`HttpExchange`](rune_http_model::HttpExchange) that HAR
//! has no field for, so a written file reads back to the same exchanges.

/// Entry: the exchange id (number).
pub const ID: &str = "_id";
/// Entry: the producing tool (string).
pub const TOOL: &str = "_tool";
/// Entry: the label (string).
pub const LABEL: &str = "_label";
/// Entry: the tags (array of strings).
pub const TAGS: &str = "_tags";
/// Entry: followed redirect hops (array of `{"status", "location"}`).
pub const REDIRECT_CHAIN: &str = "_redirectChain";
/// Response (or entry): the transport error, as Chrome writes it.
pub const ERROR: &str = "_error";
/// `content` / `postData`: content coding still applied to the body bytes.
pub const CONTENT_ENCODING: &str = "_contentEncoding";
/// `content` / `postData`: the exporter kept only part of the body.
pub const TRUNCATED: &str = "_truncated";
/// `postData`: the full body length when it was truncated.
pub const TOTAL_LEN: &str = "_totalLen";
/// `timings`: `wait` was not measured; it holds the whole `time`.
pub const WAIT_ESTIMATED: &str = "_waitEstimated";

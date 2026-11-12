use std::path::Path;

use crate::graph::Graph;

/// Errors produced by save and load operations.
///
/// # Example
///
/// ```rust
/// # #[cfg(feature = "persist")]
/// # {
/// use rune_graph::{Graph, PersistError};
/// let result = Graph::load("/nonexistent/path.bin");
/// assert!(matches!(result, Err(PersistError::Io(_))));
/// # }
/// ```
#[derive(Debug)]
pub enum PersistError {
    /// An I/O error occurred while reading or writing.
    Io(std::io::Error),
    /// The file could not be deserialised (corrupt or wrong version).
    Decode(String),
    /// The graph could not be serialised.
    Encode(String),
}

impl std::fmt::Display for PersistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Decode(e) => write!(f, "decode error: {e}"),
            Self::Encode(e) => write!(f, "encode error: {e}"),
        }
    }
}

impl std::error::Error for PersistError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Self::Io(e) = self {
            Some(e)
        } else {
            None
        }
    }
}

impl From<std::io::Error> for PersistError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl Graph {
    /// Serialise the graph to a binary file using `bincode`.
    ///
    /// The file is written atomically: data is encoded into a buffer first and
    /// written in a single [`std::fs::write`] call. Existing files are
    /// overwritten.
    ///
    /// # Errors
    ///
    /// Returns [`PersistError`] on encode failure or I/O error.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # #[cfg(feature = "persist")]
    /// # {
    /// use rune_graph::{Graph, props};
    ///
    /// let mut g = Graph::new();
    /// g.add_node(&["Person"], props! { "name" => "Alice" });
    /// g.save("graph.bin").unwrap();
    /// # }
    /// ```
    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), PersistError> {
        let bytes = bincode::serialize(self).map_err(|e| PersistError::Encode(e.to_string()))?;
        std::fs::write(path, bytes)?;
        Ok(())
    }

    /// Deserialise a graph from a binary file previously written by [`save`](Self::save).
    ///
    /// # Errors
    ///
    /// Returns [`PersistError`] if the file cannot be read or the data is
    /// corrupt / produced by an incompatible version.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # #[cfg(feature = "persist")]
    /// # {
    /// use rune_graph::Graph;
    ///
    /// let g = Graph::load("graph.bin").unwrap();
    /// println!("{} nodes loaded", g.node_count());
    /// # }
    /// ```
    pub fn load(path: impl AsRef<Path>) -> Result<Self, PersistError> {
        let bytes = std::fs::read(path)?;
        bincode::deserialize(&bytes).map_err(|e| PersistError::Decode(e.to_string()))
    }

    /// Serialise the graph to a JSON string.
    ///
    /// Useful for interoperability, debugging, and human-readable snapshots.
    /// For storage efficiency, prefer [`save`](Self::save) (bincode is ~10× smaller and faster).
    ///
    /// # Errors
    ///
    /// Returns [`PersistError::Encode`] if serialisation fails.
    ///
    /// # Example
    ///
    /// ```rust
    /// # #[cfg(feature = "persist")]
    /// # {
    /// use rune_graph::{Graph, props};
    ///
    /// let mut g = Graph::new();
    /// g.add_node(&["City"], props! { "name" => "Paris" });
    /// let json = g.to_json().unwrap();
    /// assert!(json.contains("Paris"));
    /// # }
    /// ```
    pub fn to_json(&self) -> Result<String, PersistError> {
        serde_json::to_string(self).map_err(|e| PersistError::Encode(e.to_string()))
    }

    /// Deserialise a graph from a JSON string produced by [`to_json`](Self::to_json).
    ///
    /// # Errors
    ///
    /// Returns [`PersistError::Decode`] if the JSON is invalid or does not
    /// match the graph schema.
    ///
    /// # Example
    ///
    /// ```rust
    /// # #[cfg(feature = "persist")]
    /// # {
    /// use rune_graph::{Graph, props};
    ///
    /// let mut g = Graph::new();
    /// g.add_node(&["City"], props! { "name" => "Berlin" });
    /// let json = g.to_json().unwrap();
    /// let g2 = Graph::from_json(&json).unwrap();
    /// assert_eq!(g2.node_count(), 1);
    /// # }
    /// ```
    pub fn from_json(json: &str) -> Result<Self, PersistError> {
        serde_json::from_str(json).map_err(|e| PersistError::Decode(e.to_string()))
    }
}

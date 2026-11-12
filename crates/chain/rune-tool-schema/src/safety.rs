//! [`SafetyLevel`] and [`ToolHints`]: how a tool behaves towards its target.

use std::fmt;

use serde::{Deserialize, Serialize};

/// How aggressive a tool is towards whatever it acts on.
///
/// Levels are ordered from least to most aggressive, so a policy can compare
/// them directly:
///
/// ```
/// use rune_tool_schema::SafetyLevel;
///
/// let allowed = SafetyLevel::Active;
/// assert!(SafetyLevel::Passive <= allowed);
/// assert!(SafetyLevel::Intrusive > allowed);
/// ```
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SafetyLevel {
    /// Only reads; sends nothing unusual and changes no state. Pure local
    /// computations (encoders, hashes) are passive.
    #[default]
    Passive,
    /// Sends benign requests or performs reversible changes.
    Active,
    /// Sends attack-shaped payloads or may change state irreversibly. Needs
    /// explicit opt-in.
    Intrusive,
}

impl SafetyLevel {
    /// Every level, from least to most aggressive.
    pub const ALL: [Self; 3] = [Self::Passive, Self::Active, Self::Intrusive];

    /// Lowercase name, as serialized.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Passive => "passive",
            Self::Active => "active",
            Self::Intrusive => "intrusive",
        }
    }

    /// Behaviour hints implied by this level for a tool that reaches outside
    /// the process (`open_world`). Override them with
    /// [`ToolDescriptor::with_hints`](crate::ToolDescriptor::with_hints), for
    /// example with [`ToolHints::PURE`] for local computations.
    #[must_use]
    pub const fn default_hints(self) -> ToolHints {
        match self {
            Self::Passive => ToolHints {
                read_only: true,
                destructive: false,
                idempotent: true,
                open_world: true,
            },
            Self::Active => ToolHints {
                read_only: false,
                destructive: false,
                idempotent: false,
                open_world: true,
            },
            Self::Intrusive => ToolHints::MCP_DEFAULT,
        }
    }

    /// The level a policy should assume for a tool known only by its hints,
    /// such as one listed by an external MCP server.
    ///
    /// Read-only tools are [`Passive`](Self::Passive); tools that declare
    /// themselves non-destructive are [`Active`](Self::Active); anything
    /// else (including MCP's default of "destructive") is
    /// [`Intrusive`](Self::Intrusive).
    #[must_use]
    pub const fn infer_from_hints(hints: ToolHints) -> Self {
        if hints.read_only {
            Self::Passive
        } else if !hints.destructive {
            Self::Active
        } else {
            Self::Intrusive
        }
    }
}

impl fmt::Display for SafetyLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Advisory behaviour hints, mapped one-to-one onto MCP tool annotations
/// (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`).
///
/// Hints describe a tool; they are not enforced and must not be trusted
/// when they come from an untrusted server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[expect(
    clippy::struct_excessive_bools,
    reason = "four independent MCP behaviour hints"
)]
pub struct ToolHints {
    /// The tool does not modify its environment.
    pub read_only: bool,
    /// The tool may perform destructive updates. Meaningful only when
    /// `read_only` is false.
    pub destructive: bool,
    /// Repeating a call with the same arguments has no additional effect.
    /// Meaningful only when `read_only` is false.
    pub idempotent: bool,
    /// The tool interacts with entities outside this process (network,
    /// external services) rather than a closed domain.
    pub open_world: bool,
}

impl ToolHints {
    /// A pure local computation: read-only, idempotent, closed-world.
    pub const PURE: Self = Self {
        read_only: true,
        destructive: false,
        idempotent: true,
        open_world: false,
    };

    /// The values MCP clients assume when a server omits an annotation:
    /// not read-only, destructive, not idempotent, open-world.
    pub const MCP_DEFAULT: Self = Self {
        read_only: false,
        destructive: true,
        idempotent: false,
        open_world: true,
    };

    /// Set `read_only`.
    #[must_use]
    pub const fn with_read_only(mut self, read_only: bool) -> Self {
        self.read_only = read_only;
        self
    }

    /// Set `destructive`.
    #[must_use]
    pub const fn with_destructive(mut self, destructive: bool) -> Self {
        self.destructive = destructive;
        self
    }

    /// Set `idempotent`.
    #[must_use]
    pub const fn with_idempotent(mut self, idempotent: bool) -> Self {
        self.idempotent = idempotent;
        self
    }

    /// Set `open_world`.
    #[must_use]
    pub const fn with_open_world(mut self, open_world: bool) -> Self {
        self.open_world = open_world;
        self
    }
}

impl Default for ToolHints {
    /// The hints of [`SafetyLevel::default`] (passive).
    fn default() -> Self {
        SafetyLevel::default().default_hints()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_are_ordered() {
        assert!(SafetyLevel::Passive < SafetyLevel::Active);
        assert!(SafetyLevel::Active < SafetyLevel::Intrusive);
    }

    #[test]
    fn inference_round_trips_default_hints() {
        for level in SafetyLevel::ALL {
            assert_eq!(SafetyLevel::infer_from_hints(level.default_hints()), level);
        }
        assert_eq!(
            SafetyLevel::infer_from_hints(ToolHints::MCP_DEFAULT),
            SafetyLevel::Intrusive
        );
        assert_eq!(
            SafetyLevel::infer_from_hints(ToolHints::PURE),
            SafetyLevel::Passive
        );
    }

    #[test]
    fn serde_names_match_as_str() {
        for level in SafetyLevel::ALL {
            let json = serde_json::to_value(level).unwrap();
            assert_eq!(json, level.as_str());
        }
    }
}

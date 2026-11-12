//! [`ToolDescriptor`]s for `rune-chain` tools, for MCP export and tool
//! catalogs (`rune-tool-schema`).
//!
//! ```rust
//! use rune_chain_tools::describe::{Describe, all, descriptors};
//! use rune_chain_tools::HexEncode;
//! use rune_tool_schema::{SafetyLevel, ToolCategory};
//!
//! let hex = HexEncode.descriptor();
//! assert_eq!(hex.category, Some(ToolCategory::ENCODING));
//! assert_eq!(hex.safety, SafetyLevel::Passive);
//! assert_eq!(hex.to_mcp()?.name, "hex_encode");
//!
//! assert_eq!(descriptors().len(), all().len());
//! # Ok::<(), rune_tool_schema::Error>(())
//! ```

use rune_chain_core::Tool;
use rune_tool_schema::{SafetyLevel, ToolCategory, ToolDescriptor, ToolHints};

use crate::{
    Base64Decode, Base64Encode, CaesarBrute, EntropyScore, ExtractStrings, ExtractStringsFromHex,
    HexDecode, HexEncode, Sha256, XorBrute,
};

/// Describe any [`Tool`] from its name, description and
/// [`schema`](Tool::schema).
///
/// Nothing is known about how an arbitrary tool behaves, so the descriptor
/// carries the conservative MCP default hints and the
/// [`SafetyLevel::Intrusive`] level they imply; refine them with
/// [`ToolDescriptor::with_safety`] and [`ToolDescriptor::with_hints`].
#[must_use]
pub fn describe(tool: &(impl Tool + ?Sized)) -> ToolDescriptor {
    ToolDescriptor::new(tool.name(), tool.description())
        .with_input_schema(tool.schema())
        .with_safety(SafetyLevel::Intrusive)
        .with_hints(ToolHints::MCP_DEFAULT)
}

/// A tool that knows its own [`ToolDescriptor`].
pub trait Describe {
    /// This tool's descriptor.
    fn descriptor(&self) -> ToolDescriptor;
}

/// Every tool in this crate is a pure, passive local computation.
macro_rules! describe_pure {
    ($($tool:ident => $category:ident),* $(,)?) => {
        $(
            impl Describe for $tool {
                fn descriptor(&self) -> ToolDescriptor {
                    describe(self)
                        .with_category(ToolCategory::$category)
                        .with_safety(SafetyLevel::Passive)
                        .with_hints(ToolHints::PURE)
                        .with_version(env!("CARGO_PKG_VERSION"))
                }
            }
        )*

        /// Every tool in this crate, boxed for registration with an agent or
        /// an MCP server.
        #[must_use]
        pub fn all() -> Vec<Box<dyn Tool>> {
            vec![$(Box::new($tool)),*]
        }

        /// The descriptors of [`all`] tools, in the same order.
        #[must_use]
        pub fn descriptors() -> Vec<ToolDescriptor> {
            vec![$($tool.descriptor()),*]
        }
    };
}

describe_pure! {
    HexEncode => ENCODING,
    HexDecode => ENCODING,
    Base64Encode => ENCODING,
    Base64Decode => ENCODING,
    Sha256 => HASHING,
    EntropyScore => ANALYSIS,
    ExtractStrings => ANALYSIS,
    ExtractStringsFromHex => ANALYSIS,
    CaesarBrute => CIPHER,
    XorBrute => CIPHER,
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn descriptors_match_tools_and_export_to_mcp() {
        let tools = all();
        let descriptors = descriptors();
        assert_eq!(tools.len(), descriptors.len());
        let mut names = HashSet::new();
        for (tool, descriptor) in tools.iter().zip(&descriptors) {
            assert_eq!(descriptor.name, tool.name());
            assert_eq!(descriptor.description, tool.description());
            assert_eq!(descriptor.input_schema, tool.schema());
            assert_eq!(descriptor.hints, ToolHints::PURE);
            let mcp = descriptor.to_mcp().unwrap();
            assert_eq!(mcp.to_descriptor().unwrap(), *descriptor);
            assert!(names.insert(mcp.name));
        }
    }

    #[test]
    fn unknown_tools_are_described_conservatively() {
        let descriptor = describe(&HexEncode);
        assert_eq!(descriptor.safety, SafetyLevel::Intrusive);
        assert_eq!(descriptor.hints, ToolHints::MCP_DEFAULT);
        descriptor.validate().unwrap();
    }
}

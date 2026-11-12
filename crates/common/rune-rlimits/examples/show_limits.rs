//! Prints the calling process's resource limits, `prlimit(1)` style.
//!
//! ```text
//! cargo run -p rune-rlimits --example show_limits
//! ```

use std::io::Write as _;

use rune_rlimits::{Resource, get};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut out = std::io::stdout().lock();
    writeln!(
        out,
        "{:<18} {:>22} {:>22}  UNIT",
        "RESOURCE", "SOFT", "HARD"
    )?;
    for resource in Resource::ALL {
        let limit = get(*resource)?;
        writeln!(
            out,
            "{:<18} {:>22} {:>22}  {}",
            resource.name(),
            limit.soft(),
            limit.hard(),
            resource.unit()
        )?;
    }
    Ok(())
}

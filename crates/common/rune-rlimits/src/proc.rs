//! Parsing Linux's `/proc/<pid>/limits` table.

use crate::{Error, Resource, Rlimit, Value};

/// Parses the text of a Linux `/proc/<pid>/limits` file into each
/// resource's limits, in file order.
///
/// Rows for resources this crate does not know are skipped, so a newer
/// kernel's extra rows do not break parsing. The function only reads the
/// text it is given; read the file yourself (or capture `cat
/// /proc/self/limits` from a child) to inspect another process.
///
/// ```
/// use rune_rlimits::{Resource, Rlimit, parse_proc_limits};
///
/// let text = "\
/// Limit                     Soft Limit           Hard Limit           Units
/// Max open files            1024                 524288               files
/// Max cpu time              unlimited            unlimited            seconds
/// ";
/// let limits = parse_proc_limits(text)?;
/// assert_eq!(limits[0], (Resource::NoFile, Rlimit::new(1024, 524288)?));
/// assert_eq!(limits[1], (Resource::Cpu, Rlimit::UNLIMITED));
/// # Ok::<(), rune_rlimits::Error>(())
/// ```
///
/// # Errors
///
/// [`Error::Parse`] if the header is missing or a known row lacks its
/// soft or hard value.
pub fn parse_proc_limits(text: &str) -> Result<Vec<(Resource, Rlimit)>, Error> {
    let mut lines = text.lines().enumerate();
    match lines.next() {
        Some((_, header)) if header.starts_with("Limit") => {}
        _ => {
            return Err(Error::Parse {
                line: 1,
                reason: "missing `Limit … Soft Limit … Hard Limit` header",
            });
        }
    }
    let mut out = Vec::new();
    for (index, line) in lines {
        let line_no = index + 1;
        let Some((resource, rest)) = Resource::ALL.iter().find_map(|r| {
            line.strip_prefix(r.proc_label())
                .filter(|rest| rest.starts_with(' '))
                .map(|rest| (*r, rest))
        }) else {
            continue;
        };
        let mut fields = rest.split_whitespace();
        let mut value = || -> Result<Value, Error> {
            let text = fields.next().ok_or(Error::Parse {
                line: line_no,
                reason: "row is missing a limit value",
            })?;
            text.parse().map_err(|_| Error::Parse {
                line: line_no,
                reason: "limit value is neither a number nor `unlimited`",
            })
        };
        let soft = value()?;
        let hard = value()?;
        let limit = Rlimit::new(soft, hard).map_err(|_| Error::Parse {
            line: line_no,
            reason: "soft limit exceeds hard limit",
        })?;
        out.push((resource, limit));
    }
    Ok(out)
}

#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
mod tests {
    use super::*;

    /// A real `/proc/self/limits` from Linux 7.0 (`x86_64`, systemd user
    /// session), trailing padding included.
    const LINUX_7_0: &str = "\
Limit                     Soft Limit           Hard Limit           Units
Max cpu time              unlimited            unlimited            seconds
Max file size             unlimited            unlimited            bytes
Max data size             unlimited            unlimited            bytes
Max stack size            8388608              unlimited            bytes
Max core file size        0                    unlimited            bytes
Max resident set          unlimited            unlimited            bytes
Max processes             124747               124747               processes
Max open files            524288               524288               files
Max locked memory         8388608              8388608              bytes
Max address space         unlimited            unlimited            bytes
Max file locks            unlimited            unlimited            locks
Max pending signals       124747               124747               signals
Max msgqueue size         819200               819200               bytes
Max nice priority         0                    0
Max realtime priority     0                    0
Max realtime timeout      200000               200000               us
";

    fn lookup(limits: &[(Resource, Rlimit)], resource: Resource) -> Option<Rlimit> {
        limits.iter().find(|(r, _)| *r == resource).map(|(_, l)| *l)
    }

    #[test]
    fn known_answer_linux_7_0() {
        let limits = parse_proc_limits(LINUX_7_0).unwrap();
        assert_eq!(limits.len(), Resource::ALL.len());
        let order: Vec<Resource> = limits.iter().map(|(r, _)| *r).collect();
        assert_eq!(order, Resource::ALL);
        assert_eq!(lookup(&limits, Resource::Cpu), Some(Rlimit::UNLIMITED));
        assert_eq!(
            lookup(&limits, Resource::Stack),
            Rlimit::new(8_388_608, Value::Unlimited).ok()
        );
        assert_eq!(
            lookup(&limits, Resource::Core),
            Rlimit::new(0, Value::Unlimited).ok()
        );
        assert_eq!(
            lookup(&limits, Resource::NProc),
            Some(Rlimit::fixed(124_747))
        );
        assert_eq!(
            lookup(&limits, Resource::NoFile),
            Some(Rlimit::fixed(524_288))
        );
        assert_eq!(lookup(&limits, Resource::Nice), Some(Rlimit::fixed(0)));
        assert_eq!(
            lookup(&limits, Resource::RtTime),
            Some(Rlimit::fixed(200_000))
        );
    }

    #[test]
    fn unknown_rows_are_skipped() {
        let text = "Limit  Soft Limit  Hard Limit  Units\nMax widgets  1  2  widgets\n";
        assert_eq!(parse_proc_limits(text).unwrap().len(), 0);
    }

    #[test]
    fn missing_header_is_an_error() {
        assert!(matches!(
            parse_proc_limits("Max cpu time 1 1 seconds\n"),
            Err(Error::Parse { line: 1, .. })
        ));
        assert!(parse_proc_limits("").is_err());
    }

    #[test]
    fn malformed_rows_are_errors() {
        let truncated = "Limit\nMax cpu time              5\n";
        assert!(matches!(
            parse_proc_limits(truncated),
            Err(Error::Parse { line: 2, .. })
        ));
        assert!(parse_proc_limits("Limit\nMax cpu time  lots  lots  seconds\n").is_err());
        assert!(parse_proc_limits("Limit\nMax cpu time  9  1  seconds\n").is_err());
    }
}

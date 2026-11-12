//! The standard Prometheus `process_*` metrics, read from procfs on Linux.

use crate::model::{Metric, MetricFamily, MetricType, Value};
use crate::registry::Collector;

/// Clock ticks per second used by procfs time fields (`USER_HZ`). The
/// kernel reports these fields in `USER_HZ`, which is 100 on every Linux
/// architecture's userspace ABI.
const USER_HZ: f64 = 100.0;

/// A point-in-time reading of process statistics. Fields the platform
/// cannot provide are `None` and are left out of the exposition.
#[derive(Debug, Clone, Default, PartialEq)]
#[non_exhaustive]
pub struct ProcessStats {
    /// User plus system CPU time, in seconds.
    pub cpu_seconds: Option<f64>,
    /// Resident set size, in bytes.
    pub resident_memory_bytes: Option<f64>,
    /// Virtual memory size, in bytes.
    pub virtual_memory_bytes: Option<f64>,
    /// Start time since the Unix epoch, in seconds.
    pub start_time_seconds: Option<f64>,
    /// Number of open file descriptors.
    pub open_fds: Option<f64>,
    /// Soft limit on open file descriptors.
    pub max_fds: Option<f64>,
    /// Number of OS threads.
    pub threads: Option<f64>,
}

/// The texts of the procfs files a [`ProcessStats`] is parsed from.
///
/// Parsing is sans-I/O so it can be tested with fixtures; every field is
/// optional and a missing or malformed file only drops the metrics it
/// feeds.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct ProcFiles<'a> {
    /// `/proc/self/stat`.
    pub stat: Option<&'a str>,
    /// `/proc/self/status`.
    pub status: Option<&'a str>,
    /// `/proc/stat` (for `btime`).
    pub system_stat: Option<&'a str>,
    /// `/proc/self/limits`.
    pub limits: Option<&'a str>,
    /// Number of entries in `/proc/self/fd`.
    pub open_fds: Option<usize>,
}

impl ProcessStats {
    /// Parses procfs file contents.
    ///
    /// ```
    /// use rune_metrics::{ProcFiles, ProcessStats};
    ///
    /// let mut files = ProcFiles::default();
    /// files.stat = Some(
    ///     "42 (my (odd) prog) S 1 42 42 0 -1 4194560 100 0 0 0 250 50 0 0 20 0 7 0 \
    ///      1000 104857600 2560 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 3 0 0 0 0 0",
    /// );
    /// files.system_stat = Some("cpu  1 2 3\nbtime 1700000000\n");
    /// let stats = ProcessStats::parse(&files);
    /// assert_eq!(stats.cpu_seconds, Some(3.0));
    /// assert_eq!(stats.threads, Some(7.0));
    /// assert_eq!(stats.virtual_memory_bytes, Some(104_857_600.0));
    /// assert_eq!(stats.start_time_seconds, Some(1_700_000_010.0));
    /// ```
    #[must_use]
    pub fn parse(files: &ProcFiles<'_>) -> Self {
        let mut stats = Self::default();
        let stat = files.stat.and_then(parse_stat);
        if let Some(stat) = &stat {
            stats.cpu_seconds = Some((stat.utime + stat.stime) / USER_HZ);
            stats.threads = Some(stat.threads);
            stats.virtual_memory_bytes = Some(stat.vsize);
        }
        let btime = files.system_stat.and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("btime "))
                .and_then(|v| v.trim().parse::<f64>().ok())
        });
        if let (Some(stat), Some(btime)) = (&stat, btime) {
            stats.start_time_seconds = Some(btime + stat.starttime / USER_HZ);
        }
        stats.resident_memory_bytes = files.status.and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("VmRSS:"))
                .and_then(|v| v.trim().trim_end_matches("kB").trim().parse::<f64>().ok())
                .map(|kb| kb * 1024.0)
        });
        stats.max_fds = files.limits.and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("Max open files"))
                .and_then(|rest| rest.split_whitespace().next())
                .and_then(|soft| {
                    if soft == "unlimited" {
                        Some(f64::INFINITY)
                    } else {
                        soft.parse::<f64>().ok()
                    }
                })
        });
        stats.open_fds = files.open_fds.map(usize_to_f64);
        stats
    }

    /// Reads the current process's statistics. On platforms other than
    /// Linux every field is `None`.
    #[must_use]
    pub fn read() -> Self {
        #[cfg(target_os = "linux")]
        {
            let read = |p: &str| std::fs::read_to_string(p).ok();
            let stat = read("/proc/self/stat");
            let status = read("/proc/self/status");
            let system_stat = read("/proc/stat");
            let limits = read("/proc/self/limits");
            let open_fds = std::fs::read_dir("/proc/self/fd").ok().map(Iterator::count);
            Self::parse(&ProcFiles {
                stat: stat.as_deref(),
                status: status.as_deref(),
                system_stat: system_stat.as_deref(),
                limits: limits.as_deref(),
                open_fds,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            Self::default()
        }
    }

    /// Converts the reading into `process_*` metric families.
    #[must_use]
    pub fn families(&self) -> Vec<MetricFamily> {
        let entries: [Entry<'_>; 7] = [
            (
                "process_cpu_seconds",
                "Total user and system CPU time spent in seconds.",
                Some("seconds"),
                MetricType::Counter,
                self.cpu_seconds,
            ),
            (
                "process_resident_memory_bytes",
                "Resident memory size in bytes.",
                Some("bytes"),
                MetricType::Gauge,
                self.resident_memory_bytes,
            ),
            (
                "process_virtual_memory_bytes",
                "Virtual memory size in bytes.",
                Some("bytes"),
                MetricType::Gauge,
                self.virtual_memory_bytes,
            ),
            (
                "process_start_time_seconds",
                "Start time of the process since unix epoch in seconds.",
                Some("seconds"),
                MetricType::Gauge,
                self.start_time_seconds,
            ),
            (
                "process_open_fds",
                "Number of open file descriptors.",
                None,
                MetricType::Gauge,
                self.open_fds,
            ),
            (
                "process_max_fds",
                "Maximum number of open file descriptors.",
                None,
                MetricType::Gauge,
                self.max_fds,
            ),
            (
                "process_threads",
                "Number of OS threads in the process.",
                None,
                MetricType::Gauge,
                self.threads,
            ),
        ];
        entries
            .into_iter()
            .filter_map(|(name, help, unit, kind, value)| {
                let value = value?;
                let value = match kind {
                    MetricType::Counter => Value::Counter(value),
                    _ => Value::Gauge(value),
                };
                let mut family =
                    MetricFamily::new(name, help, kind).with_metric(Metric::new(Vec::new(), value));
                family.unit = unit.map(str::to_owned);
                Some(family)
            })
            .collect()
    }
}

/// `(name, help, unit, type, value)` of one `process_*` metric.
type Entry<'a> = (&'a str, &'a str, Option<&'a str>, MetricType, Option<f64>);

#[allow(
    clippy::cast_precision_loss,
    reason = "file descriptor counts are far below 2^52"
)]
const fn usize_to_f64(n: usize) -> f64 {
    n as f64
}

struct Stat {
    utime: f64,
    stime: f64,
    threads: f64,
    starttime: f64,
    vsize: f64,
}

/// Parses `/proc/<pid>/stat`. The command name (field 2) is in parentheses
/// and may itself contain spaces and parentheses, so fields are counted
/// from the last `)`.
fn parse_stat(text: &str) -> Option<Stat> {
    let rest = &text[text.rfind(')')? + 1..];
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // `fields[0]` is field 3 (state), so field N is `fields[N - 3]`.
    let field = |n: usize| fields.get(n - 3)?.parse::<f64>().ok();
    Some(Stat {
        utime: field(14)?,
        stime: field(15)?,
        threads: field(20)?,
        starttime: field(22)?,
        vsize: field(23)?,
    })
}

/// A [`Collector`] for the standard `process_*` metrics of the current
/// process, read at every scrape.
///
/// On Linux it reports CPU time, resident and virtual memory, start time,
/// open and maximum file descriptors and thread count. Elsewhere it reports
/// nothing.
///
/// # Examples
///
/// ```
/// use rune_metrics::{Format, ProcessCollector, Registry};
///
/// let registry = Registry::new();
/// registry.register_collector(ProcessCollector::new());
/// let text = registry.encode(Format::Prometheus);
/// # #[cfg(target_os = "linux")]
/// assert!(text.contains("process_cpu_seconds_total"));
/// ```
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct ProcessCollector;

impl ProcessCollector {
    /// Creates a collector for the current process.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Collector for ProcessCollector {
    fn collect(&self) -> Vec<MetricFamily> {
        ProcessStats::read().families()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STAT: &str = "1234 (a) b) R 1 1234 1234 0 -1 4194304 500 0 0 0 \
        150 50 0 0 20 0 3 0 2500 52428800 1000 18446744073709551615 \
        1 1 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0";

    #[test]
    fn parses_procfs_fixtures() {
        let files = ProcFiles {
            stat: Some(STAT),
            status: Some("Name:\ta\nVmRSS:\t   2048 kB\nThreads:\t3\n"),
            system_stat: Some("cpu 1 2\nbtime 1600000000\nprocesses 9\n"),
            limits: Some(
                "Limit                     Soft Limit           Hard Limit           Units\n\
                 Max open files            1024                 524288               files\n",
            ),
            open_fds: Some(12),
        };
        let stats = ProcessStats::parse(&files);
        assert_eq!(stats.cpu_seconds, Some(2.0));
        assert_eq!(stats.threads, Some(3.0));
        assert_eq!(stats.virtual_memory_bytes, Some(52_428_800.0));
        assert_eq!(stats.start_time_seconds, Some(1_600_000_025.0));
        assert_eq!(stats.resident_memory_bytes, Some(2_097_152.0));
        assert_eq!(stats.max_fds, Some(1024.0));
        assert_eq!(stats.open_fds, Some(12.0));
        assert_eq!(stats.families().len(), 7);
    }

    #[test]
    fn malformed_files_drop_metrics_without_panicking() {
        let files = ProcFiles {
            stat: Some("garbage"),
            status: Some("VmRSS: lots"),
            system_stat: Some(""),
            limits: Some("Max open files unlimited unlimited files"),
            open_fds: None,
        };
        let stats = ProcessStats::parse(&files);
        assert_eq!(stats.cpu_seconds, None);
        assert_eq!(stats.resident_memory_bytes, None);
        assert_eq!(stats.max_fds, Some(f64::INFINITY));
        assert_eq!(stats.families().len(), 1);
        assert_eq!(
            ProcessStats::parse(&ProcFiles::default()).families(),
            vec![]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reads_live_process() {
        let stats = ProcessStats::read();
        assert!(stats.cpu_seconds.is_some());
        assert!(stats.resident_memory_bytes.is_some_and(|v| v > 0.0));
        assert!(stats.open_fds.is_some_and(|v| v >= 1.0));
        assert!(stats.threads.is_some_and(|v| v >= 1.0));
    }
}

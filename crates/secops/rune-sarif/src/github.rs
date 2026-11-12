//! Checks for what GitHub code scanning requires of an uploaded SARIF file.
//!
//! [`check`] reports each [`Problem`] with what GitHub does about it: it
//! rejects the upload ([`Impact::Rejected`]), or accepts it but drops or
//! ignores part of it ([`Impact::Degraded`]). The rules follow GitHub's
//! [SARIF support for code scanning][docs]: the required members, the
//! upload limits (runs, results, rules, extensions, tags, locations and
//! thread flow locations), and the `security-severity` format.
//!
//! The 10 MB limit applies to the gzip-compressed upload and is not
//! checked here. Validation against the SARIF JSON schema is a separate
//! matter; this crate's tests do it with the official schema.
//!
//! [docs]: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning

use std::collections::BTreeSet;

use crate::model::{Location, Log, ReportingDescriptor, VERSION};

/// Runs per file.
pub const MAX_RUNS: usize = 20;
/// Results per run.
pub const MAX_RESULTS: usize = 25_000;
/// Results per run that GitHub keeps (the most severe).
pub const KEPT_RESULTS: usize = 5_000;
/// Rules per run.
pub const MAX_RULES: usize = 25_000;
/// Tool extensions per run.
pub const MAX_EXTENSIONS: usize = 100;
/// Tags per rule.
pub const MAX_TAGS: usize = 20;
/// Tags per rule that GitHub keeps.
pub const KEPT_TAGS: usize = 10;
/// Locations per result.
pub const MAX_LOCATIONS: usize = 1_000;
/// Locations per result that GitHub keeps.
pub const KEPT_LOCATIONS: usize = 100;
/// Thread flow locations per result.
pub const MAX_THREAD_FLOW_LOCATIONS: usize = 10_000;
/// Thread flow locations per result that GitHub keeps.
pub const KEPT_THREAD_FLOW_LOCATIONS: usize = 1_000;

/// What GitHub code scanning does about a [`Problem`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Impact {
    /// The upload is accepted, but part of it is dropped or ignored.
    Degraded,
    /// The upload is rejected.
    Rejected,
}

/// One way a log falls short of what GitHub code scanning accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Problem {
    /// What GitHub does about it.
    pub impact: Impact,
    /// JSON path of the member, e.g. `runs[0].results[3].message.text`.
    pub path: String,
    /// What is wrong.
    pub message: String,
}

/// Every problem GitHub code scanning would have with `log`, in document
/// order. An empty list means GitHub accepts the log as it is.
///
/// # Examples
///
/// ```
/// use rune_finding::{Confidence, Finding, Location, Severity};
/// use rune_sarif::{Options, github, write};
///
/// let finding = Finding::<()>::new(
///     "py.sqli",
///     "SQL injection",
///     Severity::High,
///     Confidence::Firm,
///     Location::file("src/app.py").with_lines(15, 15),
/// );
/// let log = write(&[finding], &Options::default());
/// assert!(github::check(&log).is_empty());
/// ```
#[must_use]
pub fn check(log: &Log) -> Vec<Problem> {
    let mut problems = Problems::default();
    if log.version != VERSION {
        problems.reject("version", format!("must be \"{VERSION}\""));
    }
    if log.runs.len() > MAX_RUNS {
        problems.reject(
            "runs",
            format!("{} runs; at most {MAX_RUNS}", log.runs.len()),
        );
    }

    let mut categories = BTreeSet::new();
    for (run_index, run) in log.runs.iter().enumerate() {
        let at = format!("runs[{run_index}]");
        let tool = &run.tool;
        if tool.driver.name.trim().is_empty() {
            problems.reject(format!("{at}.tool.driver.name"), "is required");
        }
        let category = run
            .automation_details
            .as_ref()
            .and_then(|details| details.id.clone());
        if !categories.insert((tool.driver.name.clone(), category.clone())) {
            problems.reject(
                format!("{at}.automationDetails.id"),
                format!(
                    "another run of tool \"{}\" has the same category ({}); give each run its own",
                    tool.driver.name,
                    category.as_deref().unwrap_or("none")
                ),
            );
        }
        if tool.extensions.len() > MAX_EXTENSIONS {
            problems.reject(
                format!("{at}.tool.extensions"),
                format!(
                    "{} extensions; at most {MAX_EXTENSIONS}",
                    tool.extensions.len()
                ),
            );
        }
        let rule_count: usize = std::iter::once(&tool.driver)
            .chain(&tool.extensions)
            .map(|component| component.rules.len())
            .sum();
        if rule_count > MAX_RULES {
            problems.reject(
                format!("{at}.tool"),
                format!("{rule_count} rules; at most {MAX_RULES}"),
            );
        }
        for (component_at, component) in
            std::iter::once((format!("{at}.tool.driver"), &tool.driver)).chain(
                tool.extensions
                    .iter()
                    .enumerate()
                    .map(|(index, extension)| {
                        (format!("{at}.tool.extensions[{index}]"), extension)
                    }),
            )
        {
            for (rule_index, rule) in component.rules.iter().enumerate() {
                check_rule(
                    &mut problems,
                    &format!("{component_at}.rules[{rule_index}]"),
                    rule,
                );
            }
        }

        let results = &run.results;
        if results.len() > MAX_RESULTS {
            problems.reject(
                format!("{at}.results"),
                format!("{} results; at most {MAX_RESULTS}", results.len()),
            );
        } else if results.len() > KEPT_RESULTS {
            problems.degrade(
                format!("{at}.results"),
                format!(
                    "{} results; only the {KEPT_RESULTS} most severe are kept",
                    results.len()
                ),
            );
        }
        for (result_index, result) in results.iter().enumerate() {
            let at = format!("{at}.results[{result_index}]");
            if result.message.text.is_none() {
                problems.reject(format!("{at}.message.text"), "is required");
            }
            let has_rule_id = result.rule_id.is_some()
                || result.rule.as_ref().is_some_and(|rule| rule.id.is_some());
            if !has_rule_id {
                problems.reject(format!("{at}.ruleId"), "is required");
            }
            if let Some(index) = result.rule_index
                && usize::try_from(index)
                    .ok()
                    .is_none_or(|index| index >= tool.driver.rules.len())
            {
                problems.reject(
                    format!("{at}.ruleIndex"),
                    format!("{index} is not an index into tool.driver.rules"),
                );
            }
            check_security_severity(
                &mut problems,
                &format!("{at}.properties"),
                result.properties.security_severity.as_deref(),
            );
            if result.partial_fingerprints.is_empty() {
                problems.degrade(
                    format!("{at}.partialFingerprints"),
                    "missing; the upload-sarif action computes it, a direct API upload cannot \
                     track the alert across commits",
                );
            }
            check_locations(&mut problems, &at, &result.locations);
            let flow_locations: usize = result
                .code_flows
                .iter()
                .flat_map(|flow| &flow.thread_flows)
                .map(|thread| thread.locations.len())
                .sum();
            if flow_locations > MAX_THREAD_FLOW_LOCATIONS {
                problems.reject(
                    format!("{at}.codeFlows"),
                    format!(
                        "{flow_locations} thread flow locations; at most \
                         {MAX_THREAD_FLOW_LOCATIONS}"
                    ),
                );
            } else if flow_locations > KEPT_THREAD_FLOW_LOCATIONS {
                problems.degrade(
                    format!("{at}.codeFlows"),
                    format!(
                        "{flow_locations} thread flow locations; only \
                         {KEPT_THREAD_FLOW_LOCATIONS} are kept"
                    ),
                );
            }
        }
    }
    problems.0
}

/// Whether GitHub code scanning accepts `log`: [`check`] finds no problem
/// that rejects it.
#[must_use]
pub fn accepts(log: &Log) -> bool {
    check(log)
        .iter()
        .all(|problem| problem.impact != Impact::Rejected)
}

fn check_rule(problems: &mut Problems, at: &str, rule: &ReportingDescriptor) {
    if rule.id.trim().is_empty() {
        problems.reject(format!("{at}.id"), "is required");
    }
    let tags = rule.properties.tags.len();
    if tags > MAX_TAGS {
        problems.reject(
            format!("{at}.properties.tags"),
            format!("{tags} tags; at most {MAX_TAGS}"),
        );
    } else if tags > KEPT_TAGS {
        problems.degrade(
            format!("{at}.properties.tags"),
            format!("{tags} tags; only the first {KEPT_TAGS} are kept"),
        );
    }
    check_security_severity(
        problems,
        &format!("{at}.properties"),
        rule.properties.security_severity.as_deref(),
    );
}

fn check_security_severity(problems: &mut Problems, at: &str, value: Option<&str>) {
    let Some(value) = value else { return };
    let valid = value
        .trim()
        .parse::<f64>()
        .is_ok_and(|score| (0.0..=10.0).contains(&score));
    if !valid {
        problems.degrade(
            format!("{at}.security-severity"),
            format!("\"{value}\" is not a number from 0.0 to 10.0; GitHub ignores it"),
        );
    }
}

fn check_locations(problems: &mut Problems, at: &str, locations: &[Location]) {
    if locations.is_empty() {
        problems.reject(
            format!("{at}.locations"),
            "at least one location is required",
        );
    } else if locations.len() > MAX_LOCATIONS {
        problems.reject(
            format!("{at}.locations"),
            format!("{} locations; at most {MAX_LOCATIONS}", locations.len()),
        );
    } else if locations.len() > KEPT_LOCATIONS {
        problems.degrade(
            format!("{at}.locations"),
            format!(
                "{} locations; only {KEPT_LOCATIONS} are kept",
                locations.len()
            ),
        );
    }
    let Some(primary) = locations.first() else {
        return;
    };
    let at = format!("{at}.locations[0].physicalLocation");
    let Some(physical) = &primary.physical_location else {
        problems.reject(at, "is required for the primary location");
        return;
    };
    match physical
        .artifact_location
        .as_ref()
        .and_then(|artifact| artifact.uri.as_deref())
    {
        None => problems.reject(format!("{at}.artifactLocation.uri"), "is required"),
        Some(uri) => {
            if let Some((scheme, _)) = uri.split_once(':')
                && !scheme.contains('/')
                && !scheme.eq_ignore_ascii_case("file")
                && scheme.len() > 1
            {
                problems.degrade(
                    format!("{at}.artifactLocation.uri"),
                    format!(
                        "\"{uri}\" is not a file in the repository; GitHub cannot show the \
                         alert in code"
                    ),
                );
            }
        }
    }
    if physical
        .region
        .as_ref()
        .and_then(|region| region.start_line)
        .is_none()
    {
        problems.degrade(
            format!("{at}.region.startLine"),
            "missing; GitHub shows the alert on the file, not on a line",
        );
    }
}

#[derive(Default)]
struct Problems(Vec<Problem>);

impl Problems {
    fn push(&mut self, impact: Impact, path: impl Into<String>, message: impl Into<String>) {
        self.0.push(Problem {
            impact,
            path: path.into(),
            message: message.into(),
        });
    }

    fn reject(&mut self, path: impl Into<String>, message: impl Into<String>) {
        self.push(Impact::Rejected, path, message);
    }

    fn degrade(&mut self, path: impl Into<String>, message: impl Into<String>) {
        self.push(Impact::Degraded, path, message);
    }
}

#[cfg(test)]
mod tests {
    use rune_finding::{Confidence, Finding, Location, Severity};

    use super::*;
    use crate::model::{Run, ToolComponent};
    use crate::{Options, write};

    fn finding(location: Location) -> Finding {
        Finding::new("c", "t", Severity::Low, Confidence::Firm, location)
    }

    fn paths(log: &Log) -> Vec<(Impact, String)> {
        check(log)
            .into_iter()
            .map(|problem| (problem.impact, problem.path))
            .collect()
    }

    #[test]
    fn writer_output_for_code_is_clean() {
        let log = write(
            &[finding(Location::file("src/a.rs").with_lines(1, 2))],
            &Options::default(),
        );
        assert_eq!(check(&log), []);
        assert!(accepts(&log));
    }

    #[test]
    fn non_code_locations_degrade() {
        let log = write(
            &[finding(Location::url("https://x.test/"))],
            &Options::default(),
        );
        assert_eq!(
            paths(&log),
            [
                (
                    Impact::Degraded,
                    "runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri"
                        .to_owned()
                ),
                (
                    Impact::Degraded,
                    "runs[0].results[0].locations[0].physicalLocation.region.startLine".to_owned()
                ),
            ]
        );
        assert!(accepts(&log));
    }

    #[test]
    fn missing_members_reject() {
        let mut log = Log::new();
        log.version = "2.0.0".to_owned();
        let mut run = Run::default();
        run.results.push(crate::model::Result::default());
        run.results[0].rule_index = Some(3);
        run.results[0].properties.security_severity = Some("high".to_owned());
        log.runs = vec![run.clone(), run];
        let found = paths(&log);
        for expected in [
            "version",
            "runs[0].tool.driver.name",
            "runs[1].automationDetails.id",
            "runs[0].results[0].message.text",
            "runs[0].results[0].ruleId",
            "runs[0].results[0].ruleIndex",
            "runs[0].results[0].locations",
        ] {
            assert!(
                found.contains(&(Impact::Rejected, expected.to_owned())),
                "{expected}: {found:?}"
            );
        }
        assert!(found.contains(&(
            Impact::Degraded,
            "runs[0].results[0].properties.security-severity".to_owned()
        )));
        assert!(!accepts(&log));
    }

    #[test]
    fn limits() {
        let mut log = write(
            &[finding(Location::file("a").with_lines(1, 1))],
            &Options::default(),
        );
        let run = &mut log.runs[0];
        run.tool.driver.rules[0].properties.tags = (0..=MAX_TAGS).map(|n| n.to_string()).collect();
        let template = run.results[0].clone();
        run.results[0].locations = vec![template.locations[0].clone(); KEPT_LOCATIONS + 1];
        run.results.resize(KEPT_RESULTS + 1, template);
        run.tool.extensions = vec![ToolComponent::new("x"); MAX_EXTENSIONS + 1];
        let found = paths(&log);
        assert!(found.contains(&(
            Impact::Rejected,
            "runs[0].tool.driver.rules[0].properties.tags".to_owned()
        )));
        assert!(found.contains(&(Impact::Rejected, "runs[0].tool.extensions".to_owned())));
        assert!(found.contains(&(Impact::Degraded, "runs[0].results".to_owned())));
        assert!(found.contains(&(Impact::Degraded, "runs[0].results[0].locations".to_owned())));

        let mut many = Log::new();
        many.runs = (0..=MAX_RUNS)
            .map(|n| {
                let mut run = Run::default();
                run.tool.driver.name = format!("t{n}");
                run
            })
            .collect();
        assert_eq!(paths(&many), [(Impact::Rejected, "runs".to_owned())]);
    }
}

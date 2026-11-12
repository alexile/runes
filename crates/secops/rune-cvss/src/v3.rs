//! CVSS v3.0 and v3.1: [`Vector3`], its metrics and its scores.
//!
//! Specifications: [CVSS v3.1](https://www.first.org/cvss/v3.1/specification-document)
//! and [CVSS v3.0](https://www.first.org/cvss/v3.0/specification-document).
//! The formulas follow section 7 of each, evaluated exactly as FIRST's
//! reference calculators (`cvsscalc31.js`, `cvsscalc30.js`) evaluate them.
//! The two versions share their metrics and differ in two places only:
//!
//! - **Roundup.** v3.1 uses the function of its Appendix A, which first
//!   rounds to five decimal places so that floating-point noise such as
//!   `4.000000000000001` does not round up to 4.1. v3.0 rounds up directly.
//! - **Modified Impact** with a changed scope: v3.1 uses
//!   `7.52 × (MISS − 0.029) − 3.25 × (MISS × 0.9731 − 0.02)^13`, v3.0
//!   `7.52 × (MISS − 0.029) − 3.25 × (MISS − 0.02)^15`.

#![allow(
    clippy::suboptimal_flops,
    reason = "the formulas must round exactly as the reference calculators do; fusing into mul_add would change results"
)]

use core::fmt;
use core::str::FromStr;

use crate::math::powi_correctly_rounded;
use crate::metric::{metric_enum, optional, split};
use crate::{Error, Score, Severity, Version};

metric_enum! {
    /// Attack Vector (AV), and Modified Attack Vector (MAV).
    AttackVector: "AV" {
        /// N: Network.
        Network = "N",
        /// A: Adjacent Network.
        AdjacentNetwork = "A",
        /// L: Local.
        Local = "L",
        /// P: Physical.
        Physical = "P",
    }
}

metric_enum! {
    /// Attack Complexity (AC), and Modified Attack Complexity (MAC).
    AttackComplexity: "AC" {
        /// L: Low.
        Low = "L",
        /// H: High.
        High = "H",
    }
}

metric_enum! {
    /// Privileges Required (PR), and Modified Privileges Required (MPR).
    PrivilegesRequired: "PR" {
        /// N: None.
        None = "N",
        /// L: Low.
        Low = "L",
        /// H: High.
        High = "H",
    }
}

metric_enum! {
    /// User Interaction (UI), and Modified User Interaction (MUI).
    UserInteraction: "UI" {
        /// N: None.
        None = "N",
        /// R: Required.
        Required = "R",
    }
}

metric_enum! {
    /// Scope (S), and Modified Scope (MS).
    Scope: "S" {
        /// U: Unchanged.
        Unchanged = "U",
        /// C: Changed.
        Changed = "C",
    }
}

metric_enum! {
    /// Confidentiality, Integrity and Availability impact (C, I, A), and
    /// their modified forms (MC, MI, MA).
    Impact: "C/I/A" {
        /// H: High.
        High = "H",
        /// L: Low.
        Low = "L",
        /// N: None.
        None = "N",
    }
}

metric_enum! {
    /// Exploit Code Maturity (E), a temporal metric.
    ExploitCodeMaturity: "E" {
        /// U: Unproven.
        Unproven = "U",
        /// P: Proof-of-Concept.
        ProofOfConcept = "P",
        /// F: Functional.
        Functional = "F",
        /// H: High.
        High = "H",
    }
}

metric_enum! {
    /// Remediation Level (RL), a temporal metric.
    RemediationLevel: "RL" {
        /// O: Official Fix.
        OfficialFix = "O",
        /// T: Temporary Fix.
        TemporaryFix = "T",
        /// W: Workaround.
        Workaround = "W",
        /// U: Unavailable.
        Unavailable = "U",
    }
}

metric_enum! {
    /// Report Confidence (RC), a temporal metric.
    ReportConfidence: "RC" {
        /// U: Unknown.
        Unknown = "U",
        /// R: Reasonable.
        Reasonable = "R",
        /// C: Confirmed.
        Confirmed = "C",
    }
}

metric_enum! {
    /// Confidentiality, Integrity and Availability Requirement (CR, IR, AR),
    /// environmental metrics.
    Requirement: "CR/IR/AR" {
        /// L: Low.
        Low = "L",
        /// M: Medium.
        Medium = "M",
        /// H: High.
        High = "H",
    }
}

/// The CVSS v3 minor version. It changes the scoring formulas, not the
/// metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Minor {
    /// CVSS v3.0.
    V3_0,
    /// CVSS v3.1.
    V3_1,
}

impl Minor {
    /// The full version.
    #[must_use]
    pub const fn version(self) -> Version {
        match self {
            Self::V3_0 => Version::V3_0,
            Self::V3_1 => Version::V3_1,
        }
    }
}

/// The eight mandatory base metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Base {
    /// Attack Vector (AV).
    pub av: AttackVector,
    /// Attack Complexity (AC).
    pub ac: AttackComplexity,
    /// Privileges Required (PR).
    pub pr: PrivilegesRequired,
    /// User Interaction (UI).
    pub ui: UserInteraction,
    /// Scope (S).
    pub s: Scope,
    /// Confidentiality impact (C).
    pub c: Impact,
    /// Integrity impact (I).
    pub i: Impact,
    /// Availability impact (A).
    pub a: Impact,
}

/// The optional temporal metrics. `None` is Not Defined (`X`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Temporal {
    /// Exploit Code Maturity (E).
    pub e: Option<ExploitCodeMaturity>,
    /// Remediation Level (RL).
    pub rl: Option<RemediationLevel>,
    /// Report Confidence (RC).
    pub rc: Option<ReportConfidence>,
}

impl Temporal {
    /// Whether any temporal metric is defined.
    #[must_use]
    pub const fn is_defined(&self) -> bool {
        self.e.is_some() || self.rl.is_some() || self.rc.is_some()
    }
}

/// The optional environmental metrics. `None` is Not Defined (`X`); an
/// undefined modified metric takes the base metric's value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Environmental {
    /// Confidentiality Requirement (CR).
    pub cr: Option<Requirement>,
    /// Integrity Requirement (IR).
    pub ir: Option<Requirement>,
    /// Availability Requirement (AR).
    pub ar: Option<Requirement>,
    /// Modified Attack Vector (MAV).
    pub mav: Option<AttackVector>,
    /// Modified Attack Complexity (MAC).
    pub mac: Option<AttackComplexity>,
    /// Modified Privileges Required (MPR).
    pub mpr: Option<PrivilegesRequired>,
    /// Modified User Interaction (MUI).
    pub mui: Option<UserInteraction>,
    /// Modified Scope (MS).
    pub ms: Option<Scope>,
    /// Modified Confidentiality (MC).
    pub mc: Option<Impact>,
    /// Modified Integrity (MI).
    pub mi: Option<Impact>,
    /// Modified Availability (MA).
    pub ma: Option<Impact>,
}

impl Environmental {
    /// Whether any environmental metric is defined.
    #[must_use]
    pub const fn is_defined(&self) -> bool {
        self.cr.is_some()
            || self.ir.is_some()
            || self.ar.is_some()
            || self.mav.is_some()
            || self.mac.is_some()
            || self.mpr.is_some()
            || self.mui.is_some()
            || self.ms.is_some()
            || self.mc.is_some()
            || self.mi.is_some()
            || self.ma.is_some()
    }
}

/// A CVSS v3.0 or v3.1 vector.
///
/// Parse one with [`FromStr`]; [`Display`](fmt::Display) writes the
/// canonical form: the specification's metric order (Table 15), without
/// metrics that are Not Defined. Parsing accepts metrics in any order, as
/// the specification requires, and explicit `X` values.
///
/// # Examples
///
/// ```
/// use rune_cvss::{Severity, Vector3};
///
/// let vector: Vector3 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P".parse()?;
/// assert_eq!(vector.base_score().to_string(), "9.8");
/// assert_eq!(vector.temporal_score().to_string(), "9.3");
/// assert_eq!(vector.severity(), Severity::Critical);
///
/// // Any metric order parses; the canonical form uses the standard one.
/// let shuffled: Vector3 = "CVSS:3.1/E:P/S:U/AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H/RL:X".parse()?;
/// assert_eq!(shuffled, vector);
/// assert_eq!(shuffled.to_string(), "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P");
/// # Ok::<(), rune_cvss::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Vector3 {
    /// 3.0 or 3.1.
    pub minor: Minor,
    /// Base metrics.
    pub base: Base,
    /// Temporal metrics.
    pub temporal: Temporal,
    /// Environmental metrics.
    pub environmental: Environmental,
}

impl Vector3 {
    /// A vector with only base metrics.
    #[must_use]
    pub fn new(minor: Minor, base: Base) -> Self {
        Self {
            minor,
            base,
            temporal: Temporal::default(),
            environmental: Environmental::default(),
        }
    }

    /// The version: 3.0 or 3.1.
    #[must_use]
    pub const fn version(&self) -> Version {
        self.minor.version()
    }

    /// The base score.
    #[must_use]
    pub fn base_score(&self) -> Score {
        Score::from_rounded(self.base_value())
    }

    /// The temporal score. With no temporal metric defined it equals the
    /// base score.
    #[must_use]
    pub fn temporal_score(&self) -> Score {
        let Temporal { e, rl, rc } = self.temporal;
        Score::from_rounded(
            self.roundup(self.base_value() * weight::e(e) * weight::rl(rl) * weight::rc(rc)),
        )
    }

    /// The environmental score.
    ///
    /// With no environmental metric defined it usually equals the temporal
    /// score, but not always: for a changed scope, the v3.1 Modified Impact
    /// formula differs from the base Impact formula, so
    /// `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` has a base score of 9.9
    /// and an environmental score of 10.0, as in FIRST's calculator.
    #[must_use]
    pub fn environmental_score(&self) -> Score {
        let b = &self.base;
        let env = &self.environmental;
        let Temporal { e, rl, rc } = self.temporal;

        let scope = env.ms.unwrap_or(b.s);
        let c = weight::cia(env.mc.unwrap_or(b.c));
        let i = weight::cia(env.mi.unwrap_or(b.i));
        let a = weight::cia(env.ma.unwrap_or(b.a));
        let miss = (1.0
            - (1.0 - c * weight::req(env.cr))
                * (1.0 - i * weight::req(env.ir))
                * (1.0 - a * weight::req(env.ar)))
        .min(0.915);
        let modified_impact = match scope {
            Scope::Unchanged => weight::SCOPE_UNCHANGED * miss,
            Scope::Changed => match self.minor {
                Minor::V3_0 => {
                    weight::SCOPE_CHANGED * (miss - 0.029)
                        - 3.25 * powi_correctly_rounded(miss - 0.02, 15)
                }
                Minor::V3_1 => {
                    weight::SCOPE_CHANGED * (miss - 0.029)
                        - 3.25 * powi_correctly_rounded(0.9731 * miss - 0.02, 13)
                }
            },
        };
        let modified_exploitability = weight::EXPLOITABILITY
            * weight::av(env.mav.unwrap_or(b.av))
            * weight::ac(env.mac.unwrap_or(b.ac))
            * weight::pr(env.mpr.unwrap_or(b.pr), scope)
            * weight::ui(env.mui.unwrap_or(b.ui));

        if modified_impact <= 0.0 {
            return Score::ZERO;
        }
        let sum = match scope {
            Scope::Unchanged => modified_impact + modified_exploitability,
            Scope::Changed => {
                weight::SCOPE_COEFFICIENT * (modified_impact + modified_exploitability)
            }
        };
        let adjusted = self.roundup(sum.min(10.0));
        Score::from_rounded(self.roundup(adjusted * weight::e(e) * weight::rl(rl) * weight::rc(rc)))
    }

    /// The most specific score the vector supports: environmental if any
    /// environmental metric is defined, else temporal if any temporal
    /// metric is defined, else base.
    #[must_use]
    pub fn score(&self) -> Score {
        if self.environmental.is_defined() {
            self.environmental_score()
        } else if self.temporal.is_defined() {
            self.temporal_score()
        } else {
            self.base_score()
        }
    }

    /// The qualitative rating of [`score`](Self::score).
    #[must_use]
    pub fn severity(&self) -> Severity {
        self.score().severity()
    }

    /// The base score before converting to [`Score`].
    fn base_value(&self) -> f64 {
        let b = &self.base;
        let iss =
            1.0 - (1.0 - weight::cia(b.c)) * (1.0 - weight::cia(b.i)) * (1.0 - weight::cia(b.a));
        let impact = match b.s {
            Scope::Unchanged => weight::SCOPE_UNCHANGED * iss,
            Scope::Changed => {
                weight::SCOPE_CHANGED * (iss - 0.029)
                    - 3.25 * powi_correctly_rounded(iss - 0.02, 15)
            }
        };
        let exploitability = weight::EXPLOITABILITY
            * weight::av(b.av)
            * weight::ac(b.ac)
            * weight::pr(b.pr, b.s)
            * weight::ui(b.ui);
        if impact <= 0.0 {
            return 0.0;
        }
        let sum = match b.s {
            Scope::Unchanged => exploitability + impact,
            Scope::Changed => weight::SCOPE_COEFFICIENT * (exploitability + impact),
        };
        self.roundup(sum.min(10.0))
    }

    /// The version's Roundup function.
    fn roundup(&self, value: f64) -> f64 {
        match self.minor {
            Minor::V3_0 => roundup_v3_0(value),
            Minor::V3_1 => roundup_v3_1(value),
        }
    }

    pub(crate) fn parse_metrics<'a>(
        minor: Minor,
        metrics: impl Iterator<Item = Result<(&'a str, &'a str), Error>>,
    ) -> Result<Self, Error> {
        #[derive(Default)]
        struct Seen {
            av: Option<AttackVector>,
            ac: Option<AttackComplexity>,
            pr: Option<PrivilegesRequired>,
            ui: Option<UserInteraction>,
            s: Option<Scope>,
            c: Option<Impact>,
            i: Option<Impact>,
            a: Option<Impact>,
        }

        // Records `value` in `slot`, failing if the metric was already set.
        // Optional metrics track presence separately, since `X` is `None`.
        fn set<T>(slot: &mut Option<T>, metric: &'static str, value: T) -> Result<(), Error> {
            if slot.is_some() {
                return Err(Error::DuplicateMetric(metric));
            }
            *slot = Some(value);
            Ok(())
        }

        let mut base = Seen::default();
        let mut temporal = Temporal::default();
        let mut env = Environmental::default();
        // Bit `n` is set once optional metric `n` of OPTIONAL has been seen.
        let mut seen_optional: u32 = 0;

        for metric in metrics {
            let (name, value) = metric?;
            match name {
                "AV" => set(&mut base.av, "AV", AttackVector::parse(value)?)?,
                "AC" => set(&mut base.ac, "AC", AttackComplexity::parse(value)?)?,
                "PR" => set(&mut base.pr, "PR", PrivilegesRequired::parse(value)?)?,
                "UI" => set(&mut base.ui, "UI", UserInteraction::parse(value)?)?,
                "S" => set(&mut base.s, "S", Scope::parse(value)?)?,
                "C" => set(&mut base.c, "C", impact(value, "C")?)?,
                "I" => set(&mut base.i, "I", impact(value, "I")?)?,
                "A" => set(&mut base.a, "A", impact(value, "A")?)?,
                _ => {
                    let Some(index) = OPTIONAL.iter().position(|&known| known == name) else {
                        return Err(Error::UnknownMetric {
                            name: name.to_owned(),
                            version: minor.version(),
                        });
                    };
                    let metric = OPTIONAL[index];
                    if seen_optional & (1 << index) != 0 {
                        return Err(Error::DuplicateMetric(metric));
                    }
                    seen_optional |= 1 << index;
                    let invalid = |_| Error::InvalidValue {
                        metric,
                        value: value.to_owned(),
                    };
                    match metric {
                        "E" => temporal.e = optional(value, ExploitCodeMaturity::parse)?,
                        "RL" => temporal.rl = optional(value, RemediationLevel::parse)?,
                        "RC" => temporal.rc = optional(value, ReportConfidence::parse)?,
                        "CR" => env.cr = optional(value, Requirement::parse).map_err(invalid)?,
                        "IR" => env.ir = optional(value, Requirement::parse).map_err(invalid)?,
                        "AR" => env.ar = optional(value, Requirement::parse).map_err(invalid)?,
                        "MAV" => env.mav = optional(value, AttackVector::parse).map_err(invalid)?,
                        "MAC" => {
                            env.mac = optional(value, AttackComplexity::parse).map_err(invalid)?;
                        }
                        "MPR" => {
                            env.mpr =
                                optional(value, PrivilegesRequired::parse).map_err(invalid)?;
                        }
                        "MUI" => {
                            env.mui = optional(value, UserInteraction::parse).map_err(invalid)?;
                        }
                        "MS" => env.ms = optional(value, Scope::parse).map_err(invalid)?,
                        "MC" => env.mc = optional(value, Impact::parse).map_err(invalid)?,
                        "MI" => env.mi = optional(value, Impact::parse).map_err(invalid)?,
                        _ => env.ma = optional(value, Impact::parse).map_err(invalid)?,
                    }
                }
            }
        }

        let missing = |metric| Error::MissingMetric(metric);
        Ok(Self {
            minor,
            base: Base {
                av: base.av.ok_or_else(|| missing("AV"))?,
                ac: base.ac.ok_or_else(|| missing("AC"))?,
                pr: base.pr.ok_or_else(|| missing("PR"))?,
                ui: base.ui.ok_or_else(|| missing("UI"))?,
                s: base.s.ok_or_else(|| missing("S"))?,
                c: base.c.ok_or_else(|| missing("C"))?,
                i: base.i.ok_or_else(|| missing("I"))?,
                a: base.a.ok_or_else(|| missing("A"))?,
            },
            temporal,
            environmental: env,
        })
    }
}

/// Temporal and environmental metric names, in Table 15 order.
const OPTIONAL: [&str; 14] = [
    "E", "RL", "RC", "CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA",
];

/// Parses an impact value, naming the right metric in the error.
fn impact(value: &str, metric: &'static str) -> Result<Impact, Error> {
    Impact::parse(value).map_err(|_| Error::InvalidValue {
        metric,
        value: value.to_owned(),
    })
}

impl FromStr for Vector3 {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self, Error> {
        let (version, metrics) = split(text)?;
        let minor = match version {
            Version::V3_0 => Minor::V3_0,
            Version::V3_1 => Minor::V3_1,
            Version::V4_0 => return Err(Error::UnsupportedVersion(version.to_string())),
        };
        Self::parse_metrics(minor, metrics)
    }
}

impl fmt::Display for Vector3 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = &self.base;
        write!(
            f,
            "{}/AV:{}/AC:{}/PR:{}/UI:{}/S:{}/C:{}/I:{}/A:{}",
            self.version().prefix(),
            b.av,
            b.ac,
            b.pr,
            b.ui,
            b.s,
            b.c,
            b.i,
            b.a
        )?;
        let t = &self.temporal;
        let e = &self.environmental;
        write_opt(f, "E", t.e)?;
        write_opt(f, "RL", t.rl)?;
        write_opt(f, "RC", t.rc)?;
        write_opt(f, "CR", e.cr)?;
        write_opt(f, "IR", e.ir)?;
        write_opt(f, "AR", e.ar)?;
        write_opt(f, "MAV", e.mav)?;
        write_opt(f, "MAC", e.mac)?;
        write_opt(f, "MPR", e.mpr)?;
        write_opt(f, "MUI", e.mui)?;
        write_opt(f, "MS", e.ms)?;
        write_opt(f, "MC", e.mc)?;
        write_opt(f, "MI", e.mi)?;
        write_opt(f, "MA", e.ma)
    }
}

/// Writes `/NAME:VALUE` for a defined metric, nothing for Not Defined.
pub(crate) fn write_opt<T: fmt::Display>(
    f: &mut fmt::Formatter<'_>,
    name: &str,
    value: Option<T>,
) -> fmt::Result {
    value.map_or(Ok(()), |value| write!(f, "/{name}:{value}"))
}

/// CVSS v3.1 Roundup (Appendix A): the smallest number, specified to one
/// decimal place, that is equal to or higher than its input, after first
/// rounding the input to five decimal places.
#[must_use]
pub fn roundup_v3_1(value: f64) -> f64 {
    let int_input = (value * 100_000.0).round();
    if int_input % 10_000.0 == 0.0 {
        int_input / 100_000.0
    } else {
        ((int_input / 10_000.0).floor() + 1.0) / 10.0
    }
}

/// CVSS v3.0 Roundup: the smallest number, specified to one decimal place,
/// that is equal to or higher than its input.
#[must_use]
pub fn roundup_v3_0(value: f64) -> f64 {
    (value * 10.0).ceil() / 10.0
}

/// Metric weights, from section 7.4 of the specifications.
mod weight {
    use super::{
        AttackComplexity, AttackVector, ExploitCodeMaturity, Impact, PrivilegesRequired,
        RemediationLevel, ReportConfidence, Requirement, Scope, UserInteraction,
    };

    pub const EXPLOITABILITY: f64 = 8.22;
    pub const SCOPE_COEFFICIENT: f64 = 1.08;
    pub const SCOPE_UNCHANGED: f64 = 6.42;
    pub const SCOPE_CHANGED: f64 = 7.52;

    pub const fn av(value: AttackVector) -> f64 {
        match value {
            AttackVector::Network => 0.85,
            AttackVector::AdjacentNetwork => 0.62,
            AttackVector::Local => 0.55,
            AttackVector::Physical => 0.2,
        }
    }

    pub const fn ac(value: AttackComplexity) -> f64 {
        match value {
            AttackComplexity::Low => 0.77,
            AttackComplexity::High => 0.44,
        }
    }

    /// Privileges Required depends on the (modified) scope.
    pub const fn pr(value: PrivilegesRequired, scope: Scope) -> f64 {
        match (value, scope) {
            (PrivilegesRequired::None, _) => 0.85,
            (PrivilegesRequired::Low, Scope::Unchanged) => 0.62,
            (PrivilegesRequired::Low, Scope::Changed) => 0.68,
            (PrivilegesRequired::High, Scope::Unchanged) => 0.27,
            (PrivilegesRequired::High, Scope::Changed) => 0.5,
        }
    }

    pub const fn ui(value: UserInteraction) -> f64 {
        match value {
            UserInteraction::None => 0.85,
            UserInteraction::Required => 0.62,
        }
    }

    pub const fn cia(value: Impact) -> f64 {
        match value {
            Impact::High => 0.56,
            Impact::Low => 0.22,
            Impact::None => 0.0,
        }
    }

    pub const fn e(value: Option<ExploitCodeMaturity>) -> f64 {
        match value {
            None | Some(ExploitCodeMaturity::High) => 1.0,
            Some(ExploitCodeMaturity::Functional) => 0.97,
            Some(ExploitCodeMaturity::ProofOfConcept) => 0.94,
            Some(ExploitCodeMaturity::Unproven) => 0.91,
        }
    }

    pub const fn rl(value: Option<RemediationLevel>) -> f64 {
        match value {
            None | Some(RemediationLevel::Unavailable) => 1.0,
            Some(RemediationLevel::Workaround) => 0.97,
            Some(RemediationLevel::TemporaryFix) => 0.96,
            Some(RemediationLevel::OfficialFix) => 0.95,
        }
    }

    pub const fn rc(value: Option<ReportConfidence>) -> f64 {
        match value {
            None | Some(ReportConfidence::Confirmed) => 1.0,
            Some(ReportConfidence::Reasonable) => 0.96,
            Some(ReportConfidence::Unknown) => 0.92,
        }
    }

    pub const fn req(value: Option<Requirement>) -> f64 {
        match value {
            None | Some(Requirement::Medium) => 1.0,
            Some(Requirement::High) => 1.5,
            Some(Requirement::Low) => 0.5,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(text: &str) -> Vector3 {
        text.parse().unwrap()
    }

    #[test]
    fn roundup_appendix_a() {
        // The examples from Appendix A of the v3.1 specification.
        assert_eq!(roundup_v3_1(4.02), 4.1);
        assert_eq!(roundup_v3_1(4.00), 4.0);
        // Floating-point noise below the fifth decimal does not round up.
        assert_eq!(roundup_v3_1(4.000_000_000_000_001), 4.0);
        assert_eq!(roundup_v3_0(4.000_000_000_000_001), 4.1);
        assert_eq!(roundup_v3_1(0.0), 0.0);
        assert_eq!(roundup_v3_1(10.0), 10.0);
        assert_eq!(roundup_v3_1(9.000_01), 9.1);
        assert_eq!(roundup_v3_1(9.000_004), 9.0);
    }

    #[test]
    fn known_scores() {
        let cases = [
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 98, 98, 98),
            (
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                100,
                100,
                100,
            ),
            ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0, 0, 0),
            ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 99, 99, 100),
            ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 99, 99, 99),
        ];
        for (text, base, temporal, env) in cases {
            let vector = v(text);
            assert_eq!(vector.base_score().tenths(), base, "{text}");
            assert_eq!(vector.temporal_score().tenths(), temporal, "{text}");
            assert_eq!(vector.environmental_score().tenths(), env, "{text}");
        }
    }

    #[test]
    fn score_picks_the_most_specific_group() {
        let base = v("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
        assert_eq!(base.score(), base.base_score());
        let temporal = v("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H/RL:O");
        assert_eq!(temporal.score(), temporal.temporal_score());
        let env = v("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H/CR:H");
        assert_eq!(env.score(), env.environmental_score());
    }

    #[test]
    fn parse_errors() {
        let base = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
        let cases = [
            (
                format!("CVSS:3.1/{base}/AV:N"),
                Error::DuplicateMetric("AV"),
            ),
            (
                format!("CVSS:3.1/{base}/E:P/E:X"),
                Error::DuplicateMetric("E"),
            ),
            (
                format!("CVSS:3.1/{base}/E:X/E:X"),
                Error::DuplicateMetric("E"),
            ),
            (
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H".into(),
                Error::MissingMetric("A"),
            ),
            (
                format!("CVSS:3.1/{base}/AT:N"),
                Error::UnknownMetric {
                    name: "AT".into(),
                    version: Version::V3_1,
                },
            ),
            (
                format!("CVSS:3.1/{base}/E:A"),
                Error::InvalidValue {
                    metric: "E",
                    value: "A".into(),
                },
            ),
            (
                format!("CVSS:3.1/{base}/MC:S"),
                Error::InvalidValue {
                    metric: "MC",
                    value: "S".into(),
                },
            ),
            (
                "CVSS:3.1/AV:n/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".into(),
                Error::InvalidValue {
                    metric: "AV",
                    value: "n".into(),
                },
            ),
            (
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:X/A:H".into(),
                Error::InvalidValue {
                    metric: "I",
                    value: "X".into(),
                },
            ),
            (
                format!("CVSS:3.1/{base}/"),
                Error::MalformedMetric(String::new()),
            ),
            (
                format!("CVSS:3.1//{base}"),
                Error::MalformedMetric(String::new()),
            ),
            (
                format!("CVSS:3.1/{base}/E"),
                Error::MalformedMetric("E".into()),
            ),
            (
                format!("CVSS:3.1/{base}/E:"),
                Error::MalformedMetric("E:".into()),
            ),
            (base.into(), Error::MissingPrefix),
            (
                format!("CVSS:3.2/{base}"),
                Error::UnsupportedVersion("3.2".into()),
            ),
            (
                format!("CVSS:4.0/{base}"),
                Error::UnsupportedVersion("4.0".into()),
            ),
            ("CVSS:3.1".into(), Error::MissingMetric("AV")),
            (format!(" CVSS:3.1/{base}"), Error::MissingPrefix),
            (format!("cvss:3.1/{base}"), Error::MissingPrefix),
        ];
        for (text, error) in cases {
            assert_eq!(text.parse::<Vector3>(), Err(error), "{text}");
        }
    }

    #[test]
    fn explicit_not_defined_is_dropped_from_the_canonical_form() {
        let vector = v(
            "CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:C/C:L/I:N/A:N/E:X/RL:X/RC:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X",
        );
        assert_eq!(
            vector.to_string(),
            "CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:C/C:L/I:N/A:N"
        );
        assert!(!vector.temporal.is_defined());
        assert!(!vector.environmental.is_defined());
    }
}

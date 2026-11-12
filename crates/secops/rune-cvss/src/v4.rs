//! CVSS v4.0: [`Vector4`], its metrics and its score.
//!
//! Specification: [CVSS v4.0](https://www.first.org/cvss/v4.0/specification-document).
//! CVSS v4.0 has no closed-form formula. A vector is placed in one of 270
//! `MacroVector`s (equivalence classes EQ1 to EQ6), each with a score set by
//! experts, and the vector's score is interpolated from the scores of the
//! next lower `MacroVector`s by its severity distance from the highest
//! vectors of its own (section 8). This module follows FIRST's reference
//! implementation, [`cvss-v4-calculator`](https://github.com/FIRSTdotorg/cvss-v4-calculator)
//! (`cvss_score.js`), operation for operation; its data tables are vendored
//! in `lookup.rs` under their BSD-2-Clause licence.

#![allow(
    clippy::suboptimal_flops,
    reason = "the formulas must round exactly as the reference calculators do; fusing into mul_add would change results"
)]

mod lookup;

use core::fmt;
use core::str::FromStr;

use crate::math::js_round;
use crate::metric::{metric_enum, optional, split};
use crate::v3::write_opt;
use crate::{Error, Score, Severity, Version};

metric_enum! {
    /// Attack Vector (AV), and Modified Attack Vector (MAV).
    AttackVector: "AV" {
        /// N: Network.
        Network = "N",
        /// A: Adjacent.
        Adjacent = "A",
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
    /// Attack Requirements (AT), and Modified Attack Requirements (MAT).
    AttackRequirements: "AT" {
        /// N: None.
        None = "N",
        /// P: Present.
        Present = "P",
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
        /// P: Passive.
        Passive = "P",
        /// A: Active.
        Active = "A",
    }
}

metric_enum! {
    /// Impact on the vulnerable system (VC, VI, VA) or on subsequent
    /// systems (SC, SI, SA), and the modified forms MVC, MVI, MVA and MSC.
    Impact: "impact" {
        /// H: High.
        High = "H",
        /// L: Low.
        Low = "L",
        /// N: None.
        None = "N",
    }
}

metric_enum! {
    /// Modified Subsequent System Integrity and Availability (MSI, MSA),
    /// which add Safety to the impact values.
    ModifiedSubsequentImpact: "MSI/MSA" {
        /// S: Safety.
        Safety = "S",
        /// H: High.
        High = "H",
        /// L: Low.
        Low = "L",
        /// N: Negligible.
        Negligible = "N",
    }
}

metric_enum! {
    /// Exploit Maturity (E), the threat metric.
    ExploitMaturity: "E" {
        /// A: Attacked.
        Attacked = "A",
        /// P: POC.
        ProofOfConcept = "P",
        /// U: Unreported.
        Unreported = "U",
    }
}

metric_enum! {
    /// Confidentiality, Integrity and Availability Requirements (CR, IR,
    /// AR).
    Requirement: "CR/IR/AR" {
        /// H: High.
        High = "H",
        /// M: Medium.
        Medium = "M",
        /// L: Low.
        Low = "L",
    }
}

metric_enum! {
    /// Safety (S), a supplemental metric.
    Safety: "S" {
        /// N: Negligible.
        Negligible = "N",
        /// P: Present.
        Present = "P",
    }
}

metric_enum! {
    /// Automatable (AU), a supplemental metric.
    Automatable: "AU" {
        /// N: No.
        No = "N",
        /// Y: Yes.
        Yes = "Y",
    }
}

metric_enum! {
    /// Recovery (R), a supplemental metric.
    Recovery: "R" {
        /// A: Automatic.
        Automatic = "A",
        /// U: User.
        User = "U",
        /// I: Irrecoverable.
        Irrecoverable = "I",
    }
}

metric_enum! {
    /// Value Density (V), a supplemental metric.
    ValueDensity: "V" {
        /// D: Diffuse.
        Diffuse = "D",
        /// C: Concentrated.
        Concentrated = "C",
    }
}

metric_enum! {
    /// Vulnerability Response Effort (RE), a supplemental metric.
    ResponseEffort: "RE" {
        /// L: Low.
        Low = "L",
        /// M: Moderate.
        Moderate = "M",
        /// H: High.
        High = "H",
    }
}

metric_enum! {
    /// Provider Urgency (U), a supplemental metric.
    ProviderUrgency: "U" {
        /// Clear.
        Clear = "Clear",
        /// Green.
        Green = "Green",
        /// Amber.
        Amber = "Amber",
        /// Red.
        Red = "Red",
    }
}

/// The eleven mandatory base metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Base {
    /// Attack Vector (AV).
    pub av: AttackVector,
    /// Attack Complexity (AC).
    pub ac: AttackComplexity,
    /// Attack Requirements (AT).
    pub at: AttackRequirements,
    /// Privileges Required (PR).
    pub pr: PrivilegesRequired,
    /// User Interaction (UI).
    pub ui: UserInteraction,
    /// Vulnerable System Confidentiality (VC).
    pub vc: Impact,
    /// Vulnerable System Integrity (VI).
    pub vi: Impact,
    /// Vulnerable System Availability (VA).
    pub va: Impact,
    /// Subsequent System Confidentiality (SC).
    pub sc: Impact,
    /// Subsequent System Integrity (SI).
    pub si: Impact,
    /// Subsequent System Availability (SA).
    pub sa: Impact,
}

/// The optional threat metric. `None` is Not Defined (`X`), scored as
/// Attacked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Threat {
    /// Exploit Maturity (E).
    pub e: Option<ExploitMaturity>,
}

/// The optional environmental metrics. `None` is Not Defined (`X`): a
/// requirement then scores as High, a modified metric as its base metric.
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
    /// Modified Attack Requirements (MAT).
    pub mat: Option<AttackRequirements>,
    /// Modified Privileges Required (MPR).
    pub mpr: Option<PrivilegesRequired>,
    /// Modified User Interaction (MUI).
    pub mui: Option<UserInteraction>,
    /// Modified Vulnerable System Confidentiality (MVC).
    pub mvc: Option<Impact>,
    /// Modified Vulnerable System Integrity (MVI).
    pub mvi: Option<Impact>,
    /// Modified Vulnerable System Availability (MVA).
    pub mva: Option<Impact>,
    /// Modified Subsequent System Confidentiality (MSC).
    pub msc: Option<Impact>,
    /// Modified Subsequent System Integrity (MSI).
    pub msi: Option<ModifiedSubsequentImpact>,
    /// Modified Subsequent System Availability (MSA).
    pub msa: Option<ModifiedSubsequentImpact>,
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
            || self.mat.is_some()
            || self.mpr.is_some()
            || self.mui.is_some()
            || self.mvc.is_some()
            || self.mvi.is_some()
            || self.mva.is_some()
            || self.msc.is_some()
            || self.msi.is_some()
            || self.msa.is_some()
    }
}

/// The optional supplemental metrics. They describe the vulnerability but
/// never change its score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Supplemental {
    /// Safety (S).
    pub s: Option<Safety>,
    /// Automatable (AU).
    pub au: Option<Automatable>,
    /// Recovery (R).
    pub r: Option<Recovery>,
    /// Value Density (V).
    pub v: Option<ValueDensity>,
    /// Vulnerability Response Effort (RE).
    pub re: Option<ResponseEffort>,
    /// Provider Urgency (U).
    pub u: Option<ProviderUrgency>,
}

/// Which metric groups a CVSS v4.0 score covers (specification section
/// 1.3): `CVSS-B`, `CVSS-BT`, `CVSS-BE` or `CVSS-BTE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Nomenclature {
    /// Base metrics only.
    CvssB,
    /// Base and threat metrics.
    CvssBT,
    /// Base and environmental metrics.
    CvssBE,
    /// Base, threat and environmental metrics.
    CvssBTE,
}

impl Nomenclature {
    /// The name the specification uses, such as `"CVSS-BT"`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CvssB => "CVSS-B",
            Self::CvssBT => "CVSS-BT",
            Self::CvssBE => "CVSS-BE",
            Self::CvssBTE => "CVSS-BTE",
        }
    }
}

impl fmt::Display for Nomenclature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The `MacroVector` of a CVSS v4.0 vector: its level in each of the six
/// equivalence sets EQ1 to EQ6, written as six digits (`"000000"` is the
/// most severe).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacroVector {
    eq: [u8; 6],
}

impl MacroVector {
    /// The levels of EQ1 to EQ6. EQ1, EQ3, EQ4 and EQ5 range over 0..=2,
    /// EQ2 and EQ6 over 0..=1.
    #[must_use]
    pub const fn levels(self) -> [u8; 6] {
        self.eq
    }

    /// The expert-assigned score of this `MacroVector`: the score of its
    /// highest-severity vectors.
    #[must_use]
    pub fn score(self) -> Score {
        Score::from_rounded(lookup(self.eq).unwrap_or(0.0))
    }

    /// The slot of a `MacroVector` in the lookup table, or `None` when a
    /// level is out of range.
    fn index(eq: [u8; 6]) -> Option<usize> {
        let [eq1, eq2, eq3, eq4, eq5, eq6] = eq.map(usize::from);
        if eq1 > 2 || eq2 > 1 || eq3 > 2 || eq4 > 2 || eq5 > 2 || eq6 > 1 {
            return None;
        }
        Some(((((eq1 * 2 + eq2) * 3 + eq3) * 3 + eq4) * 3 + eq5) * 2 + eq6)
    }
}

impl fmt::Display for MacroVector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for level in self.eq {
            write!(f, "{level}")?;
        }
        Ok(())
    }
}

/// The score of a `MacroVector`, or `None` when it does not exist (the
/// reference implementation's `undefined`).
fn lookup(eq: [u8; 6]) -> Option<f64> {
    MacroVector::index(eq)
        .and_then(|index| lookup::MACROVECTOR_SCORES.get(index).copied().flatten())
}

/// A CVSS v4.0 vector.
///
/// Parse one with [`FromStr`]; [`Display`](fmt::Display) writes the
/// canonical form, without metrics that are Not Defined. As the
/// specification requires, parsing rejects metrics out of the order of its
/// Table 23 and accepts explicit `X` values.
///
/// # Examples
///
/// ```
/// use rune_cvss::{Severity, Vector4};
/// use rune_cvss::v4::Nomenclature;
///
/// let vector: Vector4 =
///     "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U".parse()?;
/// assert_eq!(vector.score().to_string(), "5.2");
/// assert_eq!(vector.base_score().to_string(), "7.7");
/// assert_eq!(vector.nomenclature(), Nomenclature::CvssBT);
/// assert_eq!(vector.macro_vector().to_string(), "110220");
/// assert_eq!(vector.severity(), Severity::Medium);
/// # Ok::<(), rune_cvss::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Vector4 {
    /// Base metrics.
    pub base: Base,
    /// Threat metrics.
    pub threat: Threat,
    /// Environmental metrics.
    pub environmental: Environmental,
    /// Supplemental metrics.
    pub supplemental: Supplemental,
}

/// Metric names in the order of Table 23. The first eleven are mandatory.
const ORDER: [&str; 32] = [
    "AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA", "E", "CR", "IR", "AR", "MAV",
    "MAC", "MAT", "MPR", "MUI", "MVC", "MVI", "MVA", "MSC", "MSI", "MSA", "S", "AU", "R", "V",
    "RE", "U",
];
const MANDATORY: usize = 11;

impl Vector4 {
    /// A vector with only base metrics.
    #[must_use]
    pub fn new(base: Base) -> Self {
        Self {
            base,
            threat: Threat::default(),
            environmental: Environmental::default(),
            supplemental: Supplemental::default(),
        }
    }

    /// The version, 4.0.
    #[must_use]
    pub const fn version(&self) -> Version {
        Version::V4_0
    }

    /// Which metric groups the score covers.
    #[must_use]
    pub const fn nomenclature(&self) -> Nomenclature {
        match (self.threat.e.is_some(), self.environmental.is_defined()) {
            (false, false) => Nomenclature::CvssB,
            (true, false) => Nomenclature::CvssBT,
            (false, true) => Nomenclature::CvssBE,
            (true, true) => Nomenclature::CvssBTE,
        }
    }

    /// The score, taking every defined threat and environmental metric
    /// into account (see [`nomenclature`](Self::nomenclature)).
    #[must_use]
    pub fn score(&self) -> Score {
        let effective = Effective::of(self);
        Score::from_rounded(score(&effective, effective.macro_vector()))
    }

    /// The CVSS-B score: the score of the base metrics alone, ignoring
    /// threat and environmental metrics.
    #[must_use]
    pub fn base_score(&self) -> Score {
        Self::new(self.base).score()
    }

    /// The qualitative rating of [`score`](Self::score).
    #[must_use]
    pub fn severity(&self) -> Severity {
        self.score().severity()
    }

    /// The `MacroVector` the vector falls in.
    #[must_use]
    pub fn macro_vector(&self) -> MacroVector {
        Effective::of(self).macro_vector()
    }

    pub(crate) fn parse_metrics<'a>(
        metrics: impl Iterator<Item = Result<(&'a str, &'a str), Error>>,
    ) -> Result<Self, Error> {
        let mut values: [Option<&str>; ORDER.len()] = [None; ORDER.len()];
        // Index in ORDER of the next metric allowed.
        let mut next = 0;
        for metric in metrics {
            let (name, value) = metric?;
            let Some(position) = ORDER.iter().position(|&known| known == name) else {
                return Err(Error::UnknownMetric {
                    name: name.to_owned(),
                    version: Version::V4_0,
                });
            };
            if position < next {
                return Err(if values[position].is_some() {
                    Error::DuplicateMetric(ORDER[position])
                } else {
                    Error::OutOfOrder(ORDER[position])
                });
            }
            if let Some(skipped) = ORDER[next..position.min(MANDATORY).max(next)].first() {
                return Err(Error::MissingMetric(skipped));
            }
            values[position] = Some(value);
            next = position + 1;
        }
        if let Some(missing) = ORDER[..MANDATORY].get(next) {
            return Err(Error::MissingMetric(missing));
        }

        let get = |index: usize| values.get(index).copied().flatten().unwrap_or("X");
        let impact = |index: usize| {
            Impact::parse(get(index)).map_err(|_| Error::InvalidValue {
                metric: ORDER[index],
                value: get(index).to_owned(),
            })
        };
        // Wraps an optional metric's parse error with the metric's own name.
        macro_rules! optional_metric {
            ($index:expr, $ty:ty) => {
                optional(get($index), <$ty>::parse).map_err(|_| Error::InvalidValue {
                    metric: ORDER[$index],
                    value: get($index).to_owned(),
                })?
            };
        }

        Ok(Self {
            base: Base {
                av: AttackVector::parse(get(0))?,
                ac: AttackComplexity::parse(get(1))?,
                at: AttackRequirements::parse(get(2))?,
                pr: PrivilegesRequired::parse(get(3))?,
                ui: UserInteraction::parse(get(4))?,
                vc: impact(5)?,
                vi: impact(6)?,
                va: impact(7)?,
                sc: impact(8)?,
                si: impact(9)?,
                sa: impact(10)?,
            },
            threat: Threat {
                e: optional_metric!(11, ExploitMaturity),
            },
            environmental: Environmental {
                cr: optional_metric!(12, Requirement),
                ir: optional_metric!(13, Requirement),
                ar: optional_metric!(14, Requirement),
                mav: optional_metric!(15, AttackVector),
                mac: optional_metric!(16, AttackComplexity),
                mat: optional_metric!(17, AttackRequirements),
                mpr: optional_metric!(18, PrivilegesRequired),
                mui: optional_metric!(19, UserInteraction),
                mvc: optional_metric!(20, Impact),
                mvi: optional_metric!(21, Impact),
                mva: optional_metric!(22, Impact),
                msc: optional_metric!(23, Impact),
                msi: optional_metric!(24, ModifiedSubsequentImpact),
                msa: optional_metric!(25, ModifiedSubsequentImpact),
            },
            supplemental: Supplemental {
                s: optional_metric!(26, Safety),
                au: optional_metric!(27, Automatable),
                r: optional_metric!(28, Recovery),
                v: optional_metric!(29, ValueDensity),
                re: optional_metric!(30, ResponseEffort),
                u: optional_metric!(31, ProviderUrgency),
            },
        })
    }
}

impl FromStr for Vector4 {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self, Error> {
        let (version, metrics) = split(text)?;
        if version != Version::V4_0 {
            return Err(Error::UnsupportedVersion(version.to_string()));
        }
        Self::parse_metrics(metrics)
    }
}

impl fmt::Display for Vector4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = &self.base;
        write!(
            f,
            "CVSS:4.0/AV:{}/AC:{}/AT:{}/PR:{}/UI:{}/VC:{}/VI:{}/VA:{}/SC:{}/SI:{}/SA:{}",
            b.av, b.ac, b.at, b.pr, b.ui, b.vc, b.vi, b.va, b.sc, b.si, b.sa
        )?;
        write_opt(f, "E", self.threat.e)?;
        let e = &self.environmental;
        write_opt(f, "CR", e.cr)?;
        write_opt(f, "IR", e.ir)?;
        write_opt(f, "AR", e.ar)?;
        write_opt(f, "MAV", e.mav)?;
        write_opt(f, "MAC", e.mac)?;
        write_opt(f, "MAT", e.mat)?;
        write_opt(f, "MPR", e.mpr)?;
        write_opt(f, "MUI", e.mui)?;
        write_opt(f, "MVC", e.mvc)?;
        write_opt(f, "MVI", e.mvi)?;
        write_opt(f, "MVA", e.mva)?;
        write_opt(f, "MSC", e.msc)?;
        write_opt(f, "MSI", e.msi)?;
        write_opt(f, "MSA", e.msa)?;
        let s = &self.supplemental;
        write_opt(f, "S", s.s)?;
        write_opt(f, "AU", s.au)?;
        write_opt(f, "R", s.r)?;
        write_opt(f, "V", s.v)?;
        write_opt(f, "RE", s.re)?;
        write_opt(f, "U", s.u)
    }
}

/// The metric values scoring uses, after applying the defaults (`E:X` is
/// Attacked, a requirement `X` is High) and the modified base metrics: the
/// reference implementation's `m(cvssSelected, metric)`.
///
/// Each value is held as its index into the `lookup::level` arrays, which
/// is also its position in the metric's specification order.
#[derive(Debug, Clone, Copy)]
struct Effective {
    av: usize,
    pr: usize,
    ui: usize,
    ac: usize,
    at: usize,
    vc: usize,
    vi: usize,
    va: usize,
    /// H, L, N.
    sc: usize,
    /// S, H, L, N.
    si: usize,
    /// S, H, L, N.
    sa: usize,
    cr: usize,
    ir: usize,
    ar: usize,
    /// A, P, U.
    e: usize,
}

// Level indexes, named for readability.
const N_AV: usize = 0;
const P_AV: usize = 3;
const NONE_PR_UI: usize = 0;
const LOW_AC: usize = 0;
const NONE_AT: usize = 0;
const HIGH: usize = 0;
const IMPACT_NONE: usize = 2;
const SAFETY: usize = 0;
const SUBSEQUENT_HIGH: usize = 1;
const SUBSEQUENT_NONE: usize = 3;

impl Effective {
    fn of(vector: &Vector4) -> Self {
        let b = &vector.base;
        let env = &vector.environmental;
        let impact = |value: Impact| match value {
            Impact::High => 0,
            Impact::Low => 1,
            Impact::None => 2,
        };
        // Base SI and SA have no Safety value; they map onto H, L, N.
        let subsequent = |modified: Option<ModifiedSubsequentImpact>, base: Impact| match modified {
            Some(ModifiedSubsequentImpact::Safety) => 0,
            Some(ModifiedSubsequentImpact::High) => 1,
            Some(ModifiedSubsequentImpact::Low) => 2,
            Some(ModifiedSubsequentImpact::Negligible) => 3,
            None => impact(base) + 1,
        };
        let requirement = |value: Option<Requirement>| match value {
            None | Some(Requirement::High) => 0,
            Some(Requirement::Medium) => 1,
            Some(Requirement::Low) => 2,
        };
        Self {
            av: match env.mav.unwrap_or(b.av) {
                AttackVector::Network => 0,
                AttackVector::Adjacent => 1,
                AttackVector::Local => 2,
                AttackVector::Physical => 3,
            },
            pr: match env.mpr.unwrap_or(b.pr) {
                PrivilegesRequired::None => 0,
                PrivilegesRequired::Low => 1,
                PrivilegesRequired::High => 2,
            },
            ui: match env.mui.unwrap_or(b.ui) {
                UserInteraction::None => 0,
                UserInteraction::Passive => 1,
                UserInteraction::Active => 2,
            },
            ac: match env.mac.unwrap_or(b.ac) {
                AttackComplexity::Low => 0,
                AttackComplexity::High => 1,
            },
            at: match env.mat.unwrap_or(b.at) {
                AttackRequirements::None => 0,
                AttackRequirements::Present => 1,
            },
            vc: impact(env.mvc.unwrap_or(b.vc)),
            vi: impact(env.mvi.unwrap_or(b.vi)),
            va: impact(env.mva.unwrap_or(b.va)),
            sc: impact(env.msc.unwrap_or(b.sc)),
            si: subsequent(env.msi, b.si),
            sa: subsequent(env.msa, b.sa),
            cr: requirement(env.cr),
            ir: requirement(env.ir),
            ar: requirement(env.ar),
            e: match vector.threat.e {
                None | Some(ExploitMaturity::Attacked) => 0,
                Some(ExploitMaturity::ProofOfConcept) => 1,
                Some(ExploitMaturity::Unreported) => 2,
            },
        }
    }

    /// The reference `macroVector(cvssSelected)`.
    fn macro_vector(&self) -> MacroVector {
        // EQ1: 0: AV:N and PR:N and UI:N
        //      1: (AV:N or PR:N or UI:N) and not (all three) and not AV:P
        //      2: AV:P or not (AV:N or PR:N or UI:N)
        let (av_n, pr_n, ui_n) = (
            self.av == N_AV,
            self.pr == NONE_PR_UI,
            self.ui == NONE_PR_UI,
        );
        let eq1 = if av_n && pr_n && ui_n {
            0
        } else if (av_n || pr_n || ui_n) && self.av != P_AV {
            1
        } else {
            2
        };
        // EQ2: 0: AC:L and AT:N; 1: otherwise.
        let eq2 = u8::from(!(self.ac == LOW_AC && self.at == NONE_AT));
        // EQ3: 0: VC:H and VI:H; 1: VC:H or VI:H or VA:H; 2: otherwise.
        let eq3 = if self.vc == HIGH && self.vi == HIGH {
            0
        } else if self.vc == HIGH || self.vi == HIGH || self.va == HIGH {
            1
        } else {
            2
        };
        // EQ4: 0: MSI:S or MSA:S; 1: SC:H or SI:H or SA:H; 2: otherwise.
        let eq4 = if self.si == SAFETY || self.sa == SAFETY {
            0
        } else if self.sc == HIGH || self.si == SUBSEQUENT_HIGH || self.sa == SUBSEQUENT_HIGH {
            1
        } else {
            2
        };
        // EQ5: E:A, E:P, E:U.
        #[allow(clippy::cast_possible_truncation, reason = "e is an index below 3")]
        let eq5 = self.e as u8;
        // EQ6: 0: (CR:H and VC:H) or (IR:H and VI:H) or (AR:H and VA:H).
        let eq6 = u8::from(
            !((self.cr == HIGH && self.vc == HIGH)
                || (self.ir == HIGH && self.vi == HIGH)
                || (self.ar == HIGH && self.va == HIGH)),
        );
        MacroVector {
            eq: [eq1, eq2, eq3, eq4, eq5, eq6],
        }
    }
}

/// Severity distances of a vector from one highest-severity vector of its
/// `MacroVector`, per metric (the reference `severity_distance_*`).
#[derive(Debug, Clone, Copy, Default)]
struct Distances {
    av: f64,
    pr: f64,
    ui: f64,
    ac: f64,
    at: f64,
    vc: f64,
    vi: f64,
    va: f64,
    sc: f64,
    si: f64,
    sa: f64,
    cr: f64,
    ir: f64,
    ar: f64,
}

impl Distances {
    fn any_negative(&self) -> bool {
        [
            self.av, self.pr, self.ui, self.ac, self.at, self.vc, self.vi, self.va, self.sc,
            self.si, self.sa, self.cr, self.ir, self.ar,
        ]
        .iter()
        .any(|&distance| distance < 0.0)
    }
}

/// The level value at `index`, or NaN for an out-of-range index (which the
/// tables never produce).
fn level<const N: usize>(levels: &[f64; N], index: usize) -> f64 {
    levels.get(index).copied().unwrap_or(f64::NAN)
}

/// The reference `cvss_score(...)`, before the final rounding to a
/// [`Score`]: the vector's value in 0.0..=10.0, already rounded to one
/// decimal.
#[allow(
    clippy::similar_names,
    clippy::too_many_lines,
    reason = "mirrors the reference implementation's structure and names"
)]
fn score(m: &Effective, macro_vector: MacroVector) -> f64 {
    use lookup::level as lv;

    // Exception for no impact on system (shortcut).
    if m.vc == IMPACT_NONE
        && m.vi == IMPACT_NONE
        && m.va == IMPACT_NONE
        && m.sc == IMPACT_NONE
        && m.si == SUBSEQUENT_NONE
        && m.sa == SUBSEQUENT_NONE
    {
        return 0.0;
    }

    let eq = macro_vector.eq;
    let [eq1, eq2, eq3, eq4, _, eq6] = eq;
    let Some(value) = lookup(eq) else {
        // Every MacroVector `Effective::macro_vector` produces has a score.
        return 0.0;
    };

    // 1. a. The maximal scoring difference between the MacroVector and the
    //       next lower MacroVector of each EQ, if there is one.
    let lower = |delta: [u8; 6]| {
        let mut next = eq;
        for (level, step) in next.iter_mut().zip(delta) {
            *level = level.saturating_add(step);
        }
        lookup(next)
    };
    let score_eq1_next_lower = lower([1, 0, 0, 0, 0, 0]);
    let score_eq2_next_lower = lower([0, 1, 0, 0, 0, 0]);
    // EQ3 and EQ6 are joint.
    let score_eq3eq6_next_lower = match (eq3, eq6) {
        // 11 -> 21, 01 -> 11
        (1 | 0, 1) => lower([0, 0, 1, 0, 0, 0]),
        // 10 -> 11
        (1, 0) => lower([0, 0, 0, 0, 0, 1]),
        // 00 -> 01 or 10, whichever scores higher (the right one on ties
        // or when either is missing, as in the reference).
        (0, 0) => {
            let left = lower([0, 0, 0, 0, 0, 1]);
            let right = lower([0, 0, 1, 0, 0, 0]);
            match (left, right) {
                (Some(l), Some(r)) if l > r => left,
                _ => right,
            }
        }
        // 21 -> 32, which does not exist.
        _ => lower([0, 0, 1, 0, 0, 1]),
    };
    let score_eq4_next_lower = lower([0, 0, 0, 1, 0, 0]);
    let score_eq5_next_lower = lower([0, 0, 0, 0, 1, 0]);

    // 1. b. The severity distance of the vector from a highest-severity
    //       vector of its MacroVector: the first, in the reference order,
    //       that is at least as severe in every metric. If none is, the
    //       distances to the last one are used, as in the reference.
    let eq1_maxes = lookup::MAX_EQ1
        .get(usize::from(eq1))
        .copied()
        .unwrap_or_default();
    let eq2_maxes = lookup::MAX_EQ2
        .get(usize::from(eq2))
        .copied()
        .unwrap_or_default();
    let eq3_eq6_maxes = lookup::MAX_EQ3_EQ6
        .get(usize::from(eq3))
        .and_then(|by_eq6| by_eq6.get(usize::from(eq6)))
        .copied()
        .unwrap_or_default();
    let eq4_max = lookup::MAX_EQ4
        .get(usize::from(eq4))
        .copied()
        .unwrap_or_default();

    let mut d = Distances::default();
    'search: for &[av, pr, ui] in eq1_maxes {
        for &[ac, at] in eq2_maxes {
            for &[vc, vi, va, cr, ir, ar] in eq3_eq6_maxes {
                // EQ4 and EQ5 have a single maximum each; EQ5's (E) has no
                // severity distance.
                let [sc, si, sa] = eq4_max;
                let idx = usize::from;
                d = Distances {
                    av: level(&lv::AV, m.av) - level(&lv::AV, idx(av)),
                    pr: level(&lv::PR, m.pr) - level(&lv::PR, idx(pr)),
                    ui: level(&lv::UI, m.ui) - level(&lv::UI, idx(ui)),
                    ac: level(&lv::AC, m.ac) - level(&lv::AC, idx(ac)),
                    at: level(&lv::AT, m.at) - level(&lv::AT, idx(at)),
                    vc: level(&lv::VULNERABLE, m.vc) - level(&lv::VULNERABLE, idx(vc)),
                    vi: level(&lv::VULNERABLE, m.vi) - level(&lv::VULNERABLE, idx(vi)),
                    va: level(&lv::VULNERABLE, m.va) - level(&lv::VULNERABLE, idx(va)),
                    sc: level(&lv::SC, m.sc) - level(&lv::SC, idx(sc)),
                    si: level(&lv::SI_SA, m.si) - level(&lv::SI_SA, idx(si)),
                    sa: level(&lv::SI_SA, m.sa) - level(&lv::SI_SA, idx(sa)),
                    cr: level(&lv::REQUIREMENT, m.cr) - level(&lv::REQUIREMENT, idx(cr)),
                    ir: level(&lv::REQUIREMENT, m.ir) - level(&lv::REQUIREMENT, idx(ir)),
                    ar: level(&lv::REQUIREMENT, m.ar) - level(&lv::REQUIREMENT, idx(ar)),
                };
                if !d.any_negative() {
                    break 'search;
                }
            }
        }
    }

    let current_severity_distance_eq1 = d.av + d.pr + d.ui;
    let current_severity_distance_eq2 = d.ac + d.at;
    let current_severity_distance_eq3eq6 = d.vc + d.vi + d.va + d.cr + d.ir + d.ar;
    let current_severity_distance_eq4 = d.sc + d.si + d.sa;

    let step = 0.1;
    let depth = |levels: Option<u8>| levels.map_or(f64::NAN, |n| f64::from(n) * step);
    let max_severity_eq1 = depth(lookup::DEPTH_EQ1.get(usize::from(eq1)).copied());
    let max_severity_eq2 = depth(lookup::DEPTH_EQ2.get(usize::from(eq2)).copied());
    let max_severity_eq3eq6 = depth(
        lookup::DEPTH_EQ3_EQ6
            .get(usize::from(eq3))
            .and_then(|by_eq6| by_eq6.get(usize::from(eq6)))
            .copied()
            .flatten(),
    );
    let max_severity_eq4 = depth(lookup::DEPTH_EQ4.get(usize::from(eq4)).copied());

    // 1. c./d. The proportion of the distance, times the maximal scoring
    //          difference, for each EQ that has a lower MacroVector.
    let mut n_existing_lower = 0_u8;
    let mut normalized = |next_lower: Option<f64>, distance: f64, max_severity: f64| {
        next_lower.map_or(0.0, |next| {
            n_existing_lower += 1;
            let available_distance = value - next;
            let percent_to_next_severity = distance / max_severity;
            available_distance * percent_to_next_severity
        })
    };
    let normalized_severity_eq1 = normalized(
        score_eq1_next_lower,
        current_severity_distance_eq1,
        max_severity_eq1,
    );
    let normalized_severity_eq2 = normalized(
        score_eq2_next_lower,
        current_severity_distance_eq2,
        max_severity_eq2,
    );
    let normalized_severity_eq3eq6 = normalized(
        score_eq3eq6_next_lower,
        current_severity_distance_eq3eq6,
        max_severity_eq3eq6,
    );
    let normalized_severity_eq4 = normalized(
        score_eq4_next_lower,
        current_severity_distance_eq4,
        max_severity_eq4,
    );
    // EQ5's proportion is always 0.
    let normalized_severity_eq5 = score_eq5_next_lower.map_or(0.0, |next| {
        n_existing_lower += 1;
        (value - next) * 0.0
    });

    // 2. The mean of the proportional distances.
    let mean_distance = if n_existing_lower == 0 {
        0.0
    } else {
        (normalized_severity_eq1
            + normalized_severity_eq2
            + normalized_severity_eq3eq6
            + normalized_severity_eq4
            + normalized_severity_eq5)
            / f64::from(n_existing_lower)
    };

    // 3. The MacroVector's score minus the mean distance, rounded to one
    //    decimal place.
    let value = (value - mean_distance).clamp(0.0, 10.0);
    js_round(value * 10.0) / 10.0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(text: &str) -> Vector4 {
        text.parse().unwrap()
    }

    const BASE: &str = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H";

    #[test]
    fn lookup_table_has_every_reachable_macro_vector() {
        let mut count = 0;
        for index in 0..lookup::MACROVECTOR_SLOTS {
            let digits = [
                index / 108 % 3,
                index / 54 % 2,
                index / 18 % 3,
                index / 6 % 3,
                index / 2 % 3,
                index % 2,
            ];
            let eq = digits.map(|d| u8::try_from(d).unwrap());
            assert_eq!(MacroVector::index(eq), Some(index));
            let impossible = eq[2] == 2 && eq[5] == 0;
            assert_eq!(lookup(eq).is_none(), impossible, "{eq:?}");
            if !impossible {
                count += 1;
                let score = lookup(eq).unwrap();
                assert!((0.0..=10.0).contains(&score));
            }
        }
        assert_eq!(count, 270);
        assert_eq!(lookup([0; 6]), Some(10.0));
        assert_eq!(lookup([2, 1, 2, 2, 2, 1]), Some(0.1));
        assert_eq!(lookup([3, 0, 0, 0, 0, 0]), None);
    }

    #[test]
    fn known_scores() {
        assert_eq!(v(BASE).score().tenths(), 100);
        assert_eq!(v(BASE).macro_vector().to_string(), "000100");
        let none = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N";
        assert_eq!(v(none).score(), Score::ZERO);
        // Safety lifts a no-impact vector off zero.
        let safety = v(&format!("{none}/MSI:S"));
        assert!(safety.score() > Score::ZERO);
        assert_eq!(safety.macro_vector().levels()[3], 0);
    }

    #[test]
    fn nomenclature() {
        assert_eq!(v(BASE).nomenclature(), Nomenclature::CvssB);
        assert_eq!(
            v(&format!("{BASE}/E:X/CR:X/S:P")).nomenclature(),
            Nomenclature::CvssB
        );
        assert_eq!(
            v(&format!("{BASE}/E:P")).nomenclature(),
            Nomenclature::CvssBT
        );
        assert_eq!(
            v(&format!("{BASE}/MAV:L")).nomenclature(),
            Nomenclature::CvssBE
        );
        assert_eq!(
            v(&format!("{BASE}/E:U/CR:L")).nomenclature(),
            Nomenclature::CvssBTE
        );
        assert_eq!(Nomenclature::CvssBTE.to_string(), "CVSS-BTE");
    }

    #[test]
    fn parse_errors_from_the_specification() {
        // The invalid vectors listed in section 7 of the specification.
        let cases = [
            (
                "CVSS:4.0/AV:F/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
                Error::InvalidValue {
                    metric: "AV",
                    value: "F".into(),
                },
            ),
            (
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N/E:A/E:X",
                Error::DuplicateMetric("E"),
            ),
            (
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/ui:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
                Error::UnknownMetric {
                    name: "ui".into(),
                    version: Version::V4_0,
                },
            ),
            (
                "AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
                Error::MissingPrefix,
            ),
            (
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/SC:N/SI:N/SA:N",
                Error::MissingMetric("VA"),
            ),
            (
                "CVSS:4.0/AC:L/AV:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/CR:L/IR:X/AR:L/RE:H/MAV:A/MAC:H/MAT:N/MPR:N/MUI:P/AT:N/MVC:X/MVI:N/MVA:H/MSC:N/MSI:L/MSA:S/E:U/S:N/AU:N/R:I/V:C/U:Green",
                Error::MissingMetric("AV"),
            ),
        ];
        for (text, error) in cases {
            assert_eq!(text.parse::<Vector4>(), Err(error), "{text}");
        }
    }

    #[test]
    fn parse_errors() {
        let cases = [
            (format!("{BASE}/CR:L/E:A"), Error::OutOfOrder("E")),
            (format!("{BASE}/U:Red/S:P"), Error::OutOfOrder("S")),
            (
                format!("{BASE}/U:red"),
                Error::InvalidValue {
                    metric: "U",
                    value: "red".into(),
                },
            ),
            (
                format!("{BASE}/MSC:S"),
                Error::InvalidValue {
                    metric: "MSC",
                    value: "S".into(),
                },
            ),
            (format!("{BASE}/MSI:X/MSI:S"), Error::DuplicateMetric("MSI")),
            (format!("{BASE}/AV:N"), Error::DuplicateMetric("AV")),
            (format!("{BASE}/E"), Error::MalformedMetric("E".into())),
            (format!("{BASE}/"), Error::MalformedMetric(String::new())),
            (
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:X/SC:H/SI:H/SA:H".into(),
                Error::InvalidValue {
                    metric: "VA",
                    value: "X".into(),
                },
            ),
            (
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:S/SA:H".into(),
                Error::InvalidValue {
                    metric: "SI",
                    value: "S".into(),
                },
            ),
            (
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H".into(),
                Error::MissingMetric("SA"),
            ),
            ("CVSS:4.0/AV:N/E:A".into(), Error::MissingMetric("AC")),
            ("CVSS:4.0".into(), Error::MissingMetric("AV")),
            (
                BASE.replace("4.0", "3.1"),
                Error::UnsupportedVersion("3.1".into()),
            ),
        ];
        for (text, error) in cases {
            assert_eq!(text.parse::<Vector4>(), Err(error), "{text}");
        }
    }

    #[test]
    fn canonical_form_drops_not_defined() {
        let full = format!(
            "{BASE}/E:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X/S:X/AU:X/R:X/V:X/RE:X/U:X"
        );
        assert_eq!(v(&full), v(BASE));
        assert_eq!(v(&full).to_string(), BASE);
        let all = "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/E:U/CR:L/AR:L/MAV:A/MAC:H/MAT:N/MPR:N/MUI:P/MVI:N/MVA:H/MSC:N/MSI:L/MSA:S/S:N/AU:N/R:I/V:C/RE:H/U:Green";
        assert_eq!(v(all).to_string(), all);
    }
}

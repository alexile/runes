//! EPSS scores: the FIRST [Exploit Prediction Scoring System](https://www.first.org/epss/).

use std::collections::HashMap;
use std::fmt::Write as _;

use rune_cve::CveId;

use crate::{Date, Error};

/// The EPSS score of one CVE.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub struct EpssScore {
    /// Probability, 0 to 1, that the CVE is exploited in the wild in the
    /// next 30 days.
    pub epss: f64,
    /// Share of all scored CVEs with an equal or lower score, 0 to 1.
    pub percentile: f64,
}

impl EpssScore {
    /// A score, checking that both values are finite and within 0..=1.
    #[must_use]
    pub fn new(epss: f64, percentile: f64) -> Option<Self> {
        let ok = |x: f64| (0.0..=1.0).contains(&x);
        (ok(epss) && ok(percentile)).then_some(Self { epss, percentile })
    }
}

/// All EPSS scores of one day: the daily CSV FIRST publishes
/// (`epss_scores-YYYY-MM-DD.csv.gz`), or scores collected from the EPSS
/// API.
///
/// The CSV starts with a comment carrying the model version and score
/// date, then a `cve,epss,percentile` header:
///
/// ```text
/// #model_version:v2025.03.14,score_date:2025-11-11T12:55:00Z
/// cve,epss,percentile
/// CVE-2021-44228,0.94358,0.99957
/// ```
///
/// [`to_csv`](Self::to_csv) writes the same format, so a snapshot saved
/// offline reads back with [`from_csv`](Self::from_csv).
///
/// # Examples
///
/// ```
/// use rune_epss::EpssSnapshot;
///
/// let csv = "#model_version:v2025.03.14,score_date:2025-11-11T00:00:00+0000\n\
///            cve,epss,percentile\n\
///            CVE-2021-44228,0.94358,0.99957\n";
/// let snapshot = EpssSnapshot::from_csv(csv.as_bytes())?;
/// assert_eq!(snapshot.model_version.as_deref(), Some("v2025.03.14"));
/// assert_eq!(snapshot.score_date.unwrap().to_string(), "2025-11-11");
/// let score = snapshot.get(&"CVE-2021-44228".parse()?).unwrap();
/// assert!(score.epss > 0.9);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq)]
#[non_exhaustive]
pub struct EpssSnapshot {
    /// The model version, e.g. `v2025.03.14`.
    pub model_version: Option<String>,
    /// The day the scores are for.
    pub score_date: Option<Date>,
    scores: HashMap<CveId, EpssScore>,
}

impl EpssSnapshot {
    /// An empty snapshot.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Parses the EPSS CSV.
    ///
    /// Lines starting with `#` are comments; `model_version` and
    /// `score_date` are read from them. The header must name `cve` and
    /// `epss` columns (`percentile` is optional, then 0), in any order.
    /// Blank lines and `\r\n` endings are accepted. A repeated CVE keeps
    /// its last row.
    ///
    /// # Errors
    ///
    /// [`Error::Csv`] for a missing header, a bad CVE id, or a score that
    /// is not a number between 0 and 1.
    pub fn from_csv(csv: &[u8]) -> Result<Self, Error> {
        let text = core::str::from_utf8(csv).map_err(|e| Error::Csv {
            line: csv[..e.valid_up_to()].split(|&b| b == b'\n').count(),
            reason: "not UTF-8".into(),
        })?;
        let mut out = Self::new();
        let mut columns: Option<(usize, usize, Option<usize>)> = None;
        for (n, raw) in text.lines().enumerate() {
            let line = n + 1;
            let row = raw.trim();
            if row.is_empty() {
                continue;
            }
            if let Some(comment) = row.strip_prefix('#') {
                out.read_comment(comment);
                continue;
            }
            let err = |reason: &str| Error::Csv {
                line,
                reason: reason.into(),
            };
            let Some((cve_col, epss_col, pct_col)) = columns else {
                let names: Vec<String> = row
                    .split(',')
                    .map(|c| c.trim().to_ascii_lowercase())
                    .collect();
                let find = |name: &str| names.iter().position(|c| c == name);
                columns = Some((
                    find("cve").ok_or_else(|| err("header has no `cve` column"))?,
                    find("epss").ok_or_else(|| err("header has no `epss` column"))?,
                    find("percentile"),
                ));
                continue;
            };
            let fields: Vec<&str> = row.split(',').map(str::trim).collect();
            let field = |i: usize| fields.get(i).copied().ok_or_else(|| err("too few columns"));
            let cve: CveId = field(cve_col)?.parse().map_err(|_| err("invalid CVE id"))?;
            let prob = |s: &str| s.parse::<f64>().ok().filter(|x| (0.0..=1.0).contains(x));
            let epss = prob(field(epss_col)?).ok_or_else(|| err("epss is not in 0..=1"))?;
            let percentile = match pct_col {
                Some(i) => prob(field(i)?).ok_or_else(|| err("percentile is not in 0..=1"))?,
                None => 0.0,
            };
            out.scores.insert(cve, EpssScore { epss, percentile });
        }
        if columns.is_none() {
            return Err(Error::Csv {
                line: text.lines().count().max(1),
                reason: "no header row".into(),
            });
        }
        Ok(out)
    }

    /// Parses the gzip-compressed CSV as FIRST serves it, refusing to
    /// inflate more than `max_len` bytes (the full feed is about 10 MB).
    ///
    /// # Errors
    ///
    /// [`Error::Gzip`] for a corrupt stream, [`Error::TooLarge`] past
    /// `max_len`, and the errors of [`from_csv`](Self::from_csv).
    #[cfg(feature = "gzip")]
    pub fn from_csv_gz(gz: &[u8], max_len: u64) -> Result<Self, Error> {
        use std::io::Read;
        let mut csv = Vec::new();
        flate2::read::MultiGzDecoder::new(gz)
            .take(max_len.saturating_add(1))
            .read_to_end(&mut csv)
            .map_err(Error::Gzip)?;
        if csv.len() as u64 > max_len {
            return Err(Error::TooLarge(max_len));
        }
        Self::from_csv(&csv)
    }

    fn read_comment(&mut self, comment: &str) {
        for pair in comment.split(',') {
            let Some((key, value)) = pair.split_once(':') else {
                continue;
            };
            match key.trim() {
                "model_version" => self.model_version = Some(value.trim().to_owned()),
                "score_date" => self.score_date = value.trim().parse().ok(),
                _ => {}
            }
        }
    }

    /// Writes the snapshot in the EPSS CSV format, rows in CVE id order.
    /// Scores are written with enough digits to read back exactly.
    #[must_use]
    pub fn to_csv(&self) -> String {
        let mut out = String::with_capacity(32 * self.scores.len() + 96);
        let mut meta = Vec::new();
        if let Some(v) = &self.model_version {
            meta.push(format!("model_version:{v}"));
        }
        if let Some(d) = self.score_date {
            meta.push(format!("score_date:{d}T00:00:00+0000"));
        }
        if !meta.is_empty() {
            let _ = writeln!(out, "#{}", meta.join(","));
        }
        out.push_str("cve,epss,percentile\n");
        let mut rows: Vec<_> = self.scores.iter().collect();
        rows.sort_unstable_by_key(|(id, _)| **id);
        for (id, s) in rows {
            let _ = writeln!(out, "{id},{},{}", s.epss, s.percentile);
        }
        out
    }

    /// The score of `cve`.
    #[must_use]
    pub fn get(&self, cve: &CveId) -> Option<EpssScore> {
        self.scores.get(cve).copied()
    }

    /// Adds or replaces the score of `cve`.
    pub fn insert(&mut self, cve: CveId, score: EpssScore) {
        self.scores.insert(cve, score);
    }

    /// Adds every score of `other`, replacing existing ones.
    pub fn merge(&mut self, other: Self) {
        self.scores.extend(other.scores);
        if other.model_version.is_some() {
            self.model_version = other.model_version;
        }
        if other.score_date.is_some() {
            self.score_date = other.score_date;
        }
    }

    /// Number of scored CVEs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.scores.len()
    }

    /// Whether no CVE is scored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.scores.is_empty()
    }

    /// Every score, in no particular order.
    pub fn iter(&self) -> impl Iterator<Item = (CveId, EpssScore)> + '_ {
        self.scores.iter().map(|(id, s)| (*id, *s))
    }

    /// Parses a response of the [EPSS API](https://www.first.org/epss/api)
    /// (`https://api.first.org/data/v1/epss?cve=…`). Its `epss` and
    /// `percentile` are strings or numbers; the snapshot's score date is
    /// the latest `date` in the response.
    ///
    /// # Errors
    ///
    /// [`Error::Api`] when `status` is not `OK`, [`Error::Json`] for a
    /// malformed response or an out-of-range score.
    ///
    /// # Examples
    ///
    /// ```
    /// use rune_epss::EpssSnapshot;
    ///
    /// let snapshot = EpssSnapshot::from_api_json(br#"{"status": "OK", "status-code": 200,
    ///   "total": 1, "data": [{"cve": "CVE-2022-27225", "epss": "0.000420000",
    ///   "percentile": "0.054360000", "date": "2022-03-05"}]}"#)?;
    /// assert_eq!(snapshot.get(&"CVE-2022-27225".parse()?).unwrap().epss, 0.00042);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn from_api_json(json: &[u8]) -> Result<Self, Error> {
        let response: ApiResponse = serde_json::from_slice(json)?;
        if !response.status.eq_ignore_ascii_case("OK") {
            return Err(Error::Api(response.message.unwrap_or(response.status)));
        }
        let mut out = Self::new();
        for row in response.data {
            let score = EpssScore::new(row.epss.0, row.percentile.0).ok_or_else(|| {
                Error::Json(serde::de::Error::custom(format!(
                    "{}: score out of range",
                    row.cve
                )))
            })?;
            out.scores.insert(row.cve, score);
            out.score_date = out.score_date.max(row.date);
        }
        Ok(out)
    }
}

#[derive(serde::Deserialize)]
struct ApiResponse {
    status: String,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    data: Vec<ApiRow>,
}

#[derive(serde::Deserialize)]
struct ApiRow {
    cve: CveId,
    epss: Number,
    #[serde(default)]
    percentile: Number,
    #[serde(default)]
    date: Option<Date>,
}

/// A number the API may send as a string.
#[derive(Default)]
struct Number(f64);

impl<'de> serde::Deserialize<'de> for Number {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Num(f64),
            Str(String),
        }
        match Raw::deserialize(deserializer)? {
            Raw::Num(x) => Ok(Self(x)),
            Raw::Str(s) => s.trim().parse().map(Self).map_err(serde::de::Error::custom),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CSV: &str = "#model_version:v2025.03.14,score_date:2025-11-11T00:00:00+0000\r\n\
                       cve,epss,percentile\r\n\
                       CVE-2021-44228,0.94358,0.99957\r\n\
                       \r\n\
                       CVE-2014-0160,0.94448,0.99982\r\n\
                       CVE-2022-27225,0.00042,0.05436\r\n";

    fn id(s: &str) -> CveId {
        s.parse().unwrap()
    }

    #[test]
    fn parses_csv() {
        let s = EpssSnapshot::from_csv(CSV.as_bytes()).unwrap();
        assert_eq!(s.len(), 3);
        assert_eq!(s.score_date, Date::new(2025, 11, 11));
        let heartbleed = s.get(&id("CVE-2014-0160")).unwrap();
        assert_eq!(heartbleed.epss, 0.94448);
        assert_eq!(heartbleed.percentile, 0.99982);
        assert_eq!(s.get(&id("CVE-1999-0001")), None);
    }

    #[test]
    fn column_order_and_missing_percentile() {
        let s = EpssSnapshot::from_csv(b"epss,cve\n0.5,CVE-2020-0001\n").unwrap();
        assert_eq!(
            s.get(&id("CVE-2020-0001")),
            Some(EpssScore {
                epss: 0.5,
                percentile: 0.0
            })
        );
        assert_eq!(s.model_version, None);
    }

    #[test]
    fn csv_round_trips() {
        let s = EpssSnapshot::from_csv(CSV.as_bytes()).unwrap();
        let again = EpssSnapshot::from_csv(s.to_csv().as_bytes()).unwrap();
        assert_eq!(again, s);
        assert!(
            s.to_csv()
                .starts_with("#model_version:v2025.03.14,score_date:2025-11-11")
        );
        let empty = EpssSnapshot::new();
        assert_eq!(
            EpssSnapshot::from_csv(empty.to_csv().as_bytes()).unwrap(),
            empty
        );
    }

    #[test]
    fn rejects_bad_csv() {
        let cases: [(&[u8], usize); 7] = [
            (b"", 1),
            (b"# only a comment\n", 1),
            (b"id,score\n", 1),
            (b"cve,epss\nCVE-20-1,0.1\n", 2),
            (b"cve,epss\nCVE-2020-0001,1.5\n", 2),
            (b"cve,epss\nCVE-2020-0001,NaN\n", 2),
            (b"cve,epss,percentile\nCVE-2020-0001,0.1\n", 2),
        ];
        for (csv, want) in cases {
            match EpssSnapshot::from_csv(csv) {
                Err(Error::Csv { line, .. }) => assert_eq!(line, want, "{csv:?}"),
                other => panic!("{csv:?}: {other:?}"),
            }
        }
        assert!(matches!(
            EpssSnapshot::from_csv(b"cve,epss\n\xff\n"),
            Err(Error::Csv { line: 2, .. })
        ));
    }

    #[test]
    fn merges() {
        let mut a = EpssSnapshot::from_csv(b"cve,epss\nCVE-2020-0001,0.1\n").unwrap();
        let b = EpssSnapshot::from_csv(CSV.as_bytes()).unwrap();
        a.merge(b);
        assert_eq!(a.len(), 4);
        assert_eq!(a.model_version.as_deref(), Some("v2025.03.14"));
        a.insert(id("CVE-2020-0001"), EpssScore::new(0.2, 0.3).unwrap());
        assert_eq!(a.get(&id("CVE-2020-0001")).unwrap().epss, 0.2);
        assert_eq!(a.iter().count(), 4);
        assert!(EpssScore::new(f64::NAN, 0.0).is_none());
    }

    #[test]
    fn api_json() {
        let ok = br#"{"status":"OK","status-code":200,"version":"1.0","access":"public",
            "total":2,"offset":0,"limit":100,"data":[
            {"cve":"CVE-2022-27225","epss":"0.000420000","percentile":"0.054360000","date":"2022-03-05"},
            {"cve":"CVE-2021-44228","epss":0.94358,"percentile":0.99957,"date":"2022-03-06"}]}"#;
        let s = EpssSnapshot::from_api_json(ok).unwrap();
        assert_eq!(s.len(), 2);
        assert_eq!(s.score_date, Date::new(2022, 3, 6));
        let err = br#"{"status":"error","status-code":400,"message":"Invalid parameter"}"#;
        assert!(
            matches!(EpssSnapshot::from_api_json(err), Err(Error::Api(m)) if m == "Invalid parameter")
        );
        let bad = br#"{"status":"OK","data":[{"cve":"CVE-2022-27225","epss":"2"}]}"#;
        assert!(matches!(
            EpssSnapshot::from_api_json(bad),
            Err(Error::Json(_))
        ));
        let bad = br#"{"status":"OK","data":[{"cve":"CVE-2022-27225","epss":"x"}]}"#;
        assert!(EpssSnapshot::from_api_json(bad).is_err());
    }

    #[cfg(feature = "gzip")]
    #[test]
    fn gzip() {
        use std::io::Write;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        enc.write_all(CSV.as_bytes()).unwrap();
        let gz = enc.finish().unwrap();
        let s = EpssSnapshot::from_csv_gz(&gz, 1 << 20).unwrap();
        assert_eq!(s.len(), 3);
        assert!(matches!(
            EpssSnapshot::from_csv_gz(&gz, 10),
            Err(Error::TooLarge(10))
        ));
        assert!(matches!(
            EpssSnapshot::from_csv_gz(b"not gzip", 1 << 20),
            Err(Error::Gzip(_))
        ));
    }
}

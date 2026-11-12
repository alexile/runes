//! [`Location`]: where a finding was observed.

/// Where a finding was observed.
///
/// Internally tagged with `location_kind`, in snake case:
///
/// | Variant | JSON |
/// | --- | --- |
/// | [`Url`](Self::Url) | `{"location_kind":"url","url":"https://a.test/s","parameter":"q"}` |
/// | [`Network`](Self::Network) | `{"location_kind":"network","host":"a.test","port":443}` |
/// | [`File`](Self::File) | `{"location_kind":"file","path":"src/db.py","start_line":42,"end_line":42,"start_column":5,"end_column":61,"start_byte":1200,"end_byte":1256,"snippet":"…"}` |
/// | [`ClusterObject`](Self::ClusterObject) | `{"location_kind":"cluster_object","namespace":"prod","kind":"Ingress","name":"web"}` |
/// | [`Artifact`](Self::Artifact) | `{"location_kind":"artifact","path":"bin/app","offset":4096}` |
///
/// Optional members are left out when unset. The enum is
/// `#[non_exhaustive]`; new kinds may be added in minor releases.
///
/// Variants are built with struct literals or the constructors below
/// ([`Location::url`], [`Location::file`], …); the `with_*` methods refine
/// a [`File`](Self::File) location.
///
/// # Examples
///
/// ```
/// use rune_finding::Location;
///
/// let code = Location::file("src/db.py").with_lines(42, 44).with_snippet("cursor.execute(q)");
/// assert!(matches!(code, Location::File { start_line: Some(42), .. }));
///
/// let page = Location::url("https://shop.test/search").with_parameter("q");
/// assert_eq!(page, Location::Url { url: "https://shop.test/search".into(), parameter: Some("q".into()) });
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(
    feature = "serde",
    serde(rename_all = "snake_case", tag = "location_kind")
)]
#[non_exhaustive]
pub enum Location {
    /// A network endpoint: TLS, open ports, DNS and other service checks.
    Network {
        /// Host name or IP address.
        host: String,
        /// TCP or UDP port.
        port: u16,
    },
    /// A URL, optionally at one request parameter (the DAST insertion
    /// point).
    Url {
        /// The URL as requested.
        url: String,
        /// Name of the parameter, header or cookie the issue is in.
        #[cfg_attr(
            feature = "serde",
            serde(default, skip_serializing_if = "Option::is_none")
        )]
        parameter: Option<String>,
    },
    /// A file, optionally at a region: source code for SAST and secret
    /// scanning, or a configuration file.
    ///
    /// Lines and columns are 1-based. Columns are counted however the
    /// producer counts them; byte offsets are 0-based from the start of the
    /// file. `end_*` members are inclusive of the last line, and the
    /// `end_column`/`end_byte` follow the producer's convention.
    File {
        /// Path of the file, usually relative to the scanned root.
        path: String,
        /// First line of the region.
        #[cfg_attr(
            feature = "serde",
            serde(default, skip_serializing_if = "Option::is_none")
        )]
        start_line: Option<u32>,
        /// Last line of the region.
        #[cfg_attr(
            feature = "serde",
            serde(default, skip_serializing_if = "Option::is_none")
        )]
        end_line: Option<u32>,
        /// Column of the region's start on `start_line`.
        #[cfg_attr(
            feature = "serde",
            serde(default, skip_serializing_if = "Option::is_none")
        )]
        start_column: Option<u32>,
        /// Column of the region's end on `end_line`.
        #[cfg_attr(
            feature = "serde",
            serde(default, skip_serializing_if = "Option::is_none")
        )]
        end_column: Option<u32>,
        /// Byte offset of the region's start.
        #[cfg_attr(
            feature = "serde",
            serde(default, skip_serializing_if = "Option::is_none")
        )]
        start_byte: Option<u64>,
        /// Byte offset of the region's end.
        #[cfg_attr(
            feature = "serde",
            serde(default, skip_serializing_if = "Option::is_none")
        )]
        end_byte: Option<u64>,
        /// The source text of the region. Producers truncate it to a sane
        /// length.
        #[cfg_attr(
            feature = "serde",
            serde(default, skip_serializing_if = "Option::is_none")
        )]
        snippet: Option<String>,
    },
    /// A Kubernetes object, e.g. an Ingress or a workload.
    ClusterObject {
        /// Namespace of the object.
        namespace: String,
        /// Kind of the object, e.g. `Ingress`.
        kind: String,
        /// Name of the object.
        name: String,
    },
    /// A binary artifact (ELF, PE, archive, image), optionally at a byte
    /// offset inside it.
    Artifact {
        /// Path or name of the artifact.
        path: String,
        /// Byte offset inside the artifact.
        #[cfg_attr(
            feature = "serde",
            serde(default, skip_serializing_if = "Option::is_none")
        )]
        offset: Option<u64>,
    },
}

impl Location {
    /// A URL with no parameter.
    pub fn url(url: impl Into<String>) -> Self {
        Self::Url {
            url: url.into(),
            parameter: None,
        }
    }

    /// A network endpoint.
    pub fn network(host: impl Into<String>, port: u16) -> Self {
        Self::Network {
            host: host.into(),
            port,
        }
    }

    /// A whole file, with no region yet.
    pub fn file(path: impl Into<String>) -> Self {
        Self::File {
            path: path.into(),
            start_line: None,
            end_line: None,
            start_column: None,
            end_column: None,
            start_byte: None,
            end_byte: None,
            snippet: None,
        }
    }

    /// A Kubernetes object.
    pub fn cluster_object(
        namespace: impl Into<String>,
        kind: impl Into<String>,
        name: impl Into<String>,
    ) -> Self {
        Self::ClusterObject {
            namespace: namespace.into(),
            kind: kind.into(),
            name: name.into(),
        }
    }

    /// A binary artifact, optionally at a byte offset.
    pub fn artifact(path: impl Into<String>, offset: Option<u64>) -> Self {
        Self::Artifact {
            path: path.into(),
            offset,
        }
    }

    /// Set the parameter of a [`Url`](Self::Url) location. Other kinds are
    /// returned unchanged.
    #[must_use]
    pub fn with_parameter(mut self, name: impl Into<String>) -> Self {
        if let Self::Url { parameter, .. } = &mut self {
            *parameter = Some(name.into());
        }
        self
    }

    /// Set the line range of a [`File`](Self::File) location. Other kinds
    /// are returned unchanged.
    #[must_use]
    pub const fn with_lines(mut self, start: u32, end: u32) -> Self {
        if let Self::File {
            start_line,
            end_line,
            ..
        } = &mut self
        {
            *start_line = Some(start);
            *end_line = Some(end);
        }
        self
    }

    /// Set the column range of a [`File`](Self::File) location. Other kinds
    /// are returned unchanged.
    #[must_use]
    pub const fn with_columns(mut self, start: u32, end: u32) -> Self {
        if let Self::File {
            start_column,
            end_column,
            ..
        } = &mut self
        {
            *start_column = Some(start);
            *end_column = Some(end);
        }
        self
    }

    /// Set the byte range of a [`File`](Self::File) location. Other kinds
    /// are returned unchanged.
    #[must_use]
    pub const fn with_bytes(mut self, start: u64, end: u64) -> Self {
        if let Self::File {
            start_byte,
            end_byte,
            ..
        } = &mut self
        {
            *start_byte = Some(start);
            *end_byte = Some(end);
        }
        self
    }

    /// Set the snippet of a [`File`](Self::File) location. Other kinds are
    /// returned unchanged.
    #[must_use]
    pub fn with_snippet(mut self, text: impl Into<String>) -> Self {
        if let Self::File { snippet, .. } = &mut self {
            *snippet = Some(text.into());
        }
        self
    }

    /// The `location_kind` tag of this location, e.g. `"url"`.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Network { .. } => "network",
            Self::Url { .. } => "url",
            Self::File { .. } => "file",
            Self::ClusterObject { .. } => "cluster_object",
            Self::Artifact { .. } => "artifact",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refiners_touch_only_their_kind() {
        let file = Location::file("a.rs")
            .with_lines(1, 2)
            .with_columns(3, 4)
            .with_bytes(5, 6)
            .with_snippet("x")
            .with_parameter("ignored");
        assert_eq!(
            file,
            Location::File {
                path: "a.rs".to_owned(),
                start_line: Some(1),
                end_line: Some(2),
                start_column: Some(3),
                end_column: Some(4),
                start_byte: Some(5),
                end_byte: Some(6),
                snippet: Some("x".to_owned()),
            }
        );
        let network = Location::network("h", 1);
        assert_eq!(
            network
                .clone()
                .with_lines(1, 2)
                .with_columns(1, 2)
                .with_bytes(1, 2)
                .with_snippet("s")
                .with_parameter("p"),
            network
        );
    }

    #[test]
    fn kinds() {
        let all = [
            Location::network("h", 1),
            Location::url("u"),
            Location::file("f"),
            Location::cluster_object("n", "k", "o"),
            Location::artifact("a", Some(1)),
        ];
        let kinds: Vec<_> = all.iter().map(Location::kind).collect();
        assert_eq!(
            kinds,
            ["network", "url", "file", "cluster_object", "artifact"]
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_shape_matches_kind() {
        for location in [
            Location::network("h", 1),
            Location::url("u").with_parameter("q"),
            Location::file("f").with_lines(1, 1),
            Location::cluster_object("n", "k", "o"),
            Location::artifact("a", None),
        ] {
            let json = serde_json::to_value(&location).unwrap();
            assert_eq!(json["location_kind"], location.kind());
            assert_eq!(serde_json::from_value::<Location>(json).unwrap(), location);
        }
        assert_eq!(
            serde_json::to_string(&Location::file("f")).unwrap(),
            r#"{"location_kind":"file","path":"f"}"#
        );
    }
}

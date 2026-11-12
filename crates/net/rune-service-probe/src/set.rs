//! A collection of probes, looked up by id or port.

use std::fmt;

use crate::ServiceProbe;

/// A set of probes, for callers that pick a probe per target: by id from a
/// template, or by port in a port scanner.
///
/// ```
/// use rune_service_probe::banner::BannerProbe;
/// use rune_service_probe::ProbeSet;
///
/// let mut probes = ProbeSet::new();
/// probes.push(BannerProbe::new());
/// assert!(probes.get("banner").is_some());
/// assert_eq!(probes.for_port(22).count(), 0); // the banner probe has no well-known port
/// ```
#[derive(Default)]
pub struct ProbeSet {
    probes: Vec<Box<dyn ServiceProbe>>,
}

impl fmt::Debug for ProbeSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.probes.iter().map(|probe| probe.id()))
            .finish()
    }
}

impl ProbeSet {
    /// An empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a probe. Ids are not deduplicated: [`get`](Self::get) returns
    /// the first probe added with an id.
    pub fn push(&mut self, probe: impl ServiceProbe + 'static) -> &mut Self {
        self.probes.push(Box::new(probe));
        self
    }

    /// Add a boxed probe.
    pub fn push_boxed(&mut self, probe: Box<dyn ServiceProbe>) -> &mut Self {
        self.probes.push(probe);
        self
    }

    /// The first probe with this id.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&dyn ServiceProbe> {
        self.iter().find(|probe| probe.id() == id)
    }

    /// The probes whose [`default_ports`](ServiceProbe::default_ports)
    /// include `port`, in insertion order.
    pub fn for_port(&self, port: u16) -> impl Iterator<Item = &dyn ServiceProbe> {
        self.iter()
            .filter(move |probe| probe.default_ports().contains(&port))
    }

    /// Every probe, in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = &dyn ServiceProbe> {
        self.probes.iter().map(AsRef::as_ref)
    }

    /// Number of probes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.probes.len()
    }

    /// True when the set has no probes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.probes.is_empty()
    }
}

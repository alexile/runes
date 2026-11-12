//! The registry of policy-controlled features.

/// How much harm granting a feature to every origin can do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Sensitivity {
    /// Layout, media and client-hint features; granting them widely is
    /// rarely a problem.
    Low,
    /// Sensors, clipboard writes, device lists, advertising and storage
    /// APIs: fingerprinting, tracking or nuisance potential.
    Moderate,
    /// Camera, microphone, location, screen capture, payments, hardware
    /// access and credentials: direct access to the user or their devices.
    High,
}

impl Sensitivity {
    /// The lowercase name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Moderate => "moderate",
            Self::High => "high",
        }
    }
}

/// Whether a feature is still supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Status {
    /// Defined by a current specification or shipped in a browser.
    Current,
    /// Removed, renamed or never shipped; browsers ignore it.
    Deprecated,
}

/// A known policy-controlled feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Feature {
    /// The feature name as written in the header.
    pub name: &'static str,
    /// How much granting it to every origin matters.
    pub sensitivity: Sensitivity,
    /// Whether browsers still support it.
    pub status: Status,
}

use Sensitivity::{High, Low, Moderate};
use Status::{Current, Deprecated};

const fn f(name: &'static str, sensitivity: Sensitivity, status: Status) -> Feature {
    Feature {
        name,
        sensitivity,
        status,
    }
}

/// Every feature this crate knows, sorted by name. Sources: the
/// [W3C features list](https://github.com/w3c/webappsec-permissions-policy/blob/main/features.md)
/// and Chromium's `permissions_policy_features.json5`.
pub const FEATURES: &[Feature] = &[
    f("accelerometer", Moderate, Current),
    f("all-screens-capture", High, Current),
    f("ambient-light-sensor", Moderate, Current),
    f("attribution-reporting", Moderate, Current),
    f("autoplay", Low, Current),
    f("battery", Moderate, Current),
    f("bluetooth", High, Current),
    f("browsing-topics", Moderate, Current),
    f("camera", High, Current),
    f("captured-surface-control", Moderate, Current),
    f("ch-device-memory", Low, Current),
    f("ch-downlink", Low, Current),
    f("ch-dpr", Low, Current),
    f("ch-ect", Low, Current),
    f("ch-prefers-color-scheme", Low, Current),
    f("ch-prefers-reduced-motion", Low, Current),
    f("ch-prefers-reduced-transparency", Low, Current),
    f("ch-rtt", Low, Current),
    f("ch-save-data", Low, Current),
    f("ch-ua", Low, Current),
    f("ch-ua-arch", Low, Current),
    f("ch-ua-bitness", Low, Current),
    f("ch-ua-form-factors", Low, Current),
    f("ch-ua-full-version", Low, Current),
    f("ch-ua-full-version-list", Low, Current),
    f("ch-ua-mobile", Low, Current),
    f("ch-ua-model", Low, Current),
    f("ch-ua-platform", Low, Current),
    f("ch-ua-platform-version", Low, Current),
    f("ch-ua-wow64", Low, Current),
    f("ch-viewport-height", Low, Current),
    f("ch-viewport-width", Low, Current),
    f("ch-width", Low, Current),
    f("clipboard-read", High, Current),
    f("clipboard-write", Moderate, Current),
    f("compute-pressure", Low, Current),
    f("conversion-measurement", Moderate, Deprecated),
    f("cross-origin-isolated", Low, Current),
    f("deferred-fetch", Low, Current),
    f("deferred-fetch-minimal", Low, Current),
    f("digital-credentials-get", High, Current),
    f("direct-sockets", High, Current),
    f("display-capture", High, Current),
    f("document-domain", Moderate, Deprecated),
    f("document-write", Low, Deprecated),
    f("encrypted-media", Low, Current),
    f("execution-while-not-rendered", Low, Current),
    f("execution-while-out-of-viewport", Low, Current),
    f("focus-without-user-activation", Low, Current),
    f("fullscreen", Low, Current),
    f("gamepad", Low, Current),
    f("geolocation", High, Current),
    f("gyroscope", Moderate, Current),
    f("hid", High, Current),
    f("identity-credentials-get", High, Current),
    f("idle-detection", Moderate, Current),
    f("interest-cohort", Moderate, Deprecated),
    f("join-ad-interest-group", Moderate, Current),
    f("keyboard-map", Moderate, Current),
    f("language-detector", Low, Current),
    f("layout-animations", Low, Deprecated),
    f("lazyload", Low, Deprecated),
    f("legacy-image-formats", Low, Deprecated),
    f("local-fonts", Moderate, Current),
    f("magnetometer", Moderate, Current),
    f("microphone", High, Current),
    f("midi", Moderate, Current),
    f("navigation-override", Low, Current),
    f("otp-credentials", High, Current),
    f("oversized-images", Low, Deprecated),
    f("payment", High, Current),
    f("picture-in-picture", Low, Current),
    f("private-aggregation", Moderate, Current),
    f("private-state-token-issuance", Moderate, Current),
    f("private-state-token-redemption", Moderate, Current),
    f("publickey-credentials-create", High, Current),
    f("publickey-credentials-get", High, Current),
    f("rewriter", Low, Current),
    f("run-ad-auction", Moderate, Current),
    f("screen-wake-lock", Low, Current),
    f("serial", High, Current),
    f("shared-autofill", Moderate, Current),
    f("shared-storage", Moderate, Current),
    f("shared-storage-select-url", Moderate, Current),
    f("smart-card", High, Current),
    f("speaker", Moderate, Deprecated),
    f("speaker-selection", Moderate, Current),
    f("storage-access", Moderate, Current),
    f("summarizer", Low, Current),
    f("sync-script", Low, Deprecated),
    f("sync-xhr", Low, Current),
    f("translator", Low, Current),
    f("trust-token-redemption", Moderate, Deprecated),
    f("unload", Low, Current),
    f("unoptimized-images", Low, Deprecated),
    f("unsized-media", Low, Deprecated),
    f("usb", High, Current),
    f("vertical-scroll", Low, Deprecated),
    f("vibrate", Low, Deprecated),
    f("vr", High, Deprecated),
    f("wake-lock", Low, Deprecated),
    f("web-printing", Moderate, Current),
    f("web-share", Low, Current),
    f("window-management", Moderate, Current),
    f("writer", Low, Current),
    f("xr-spatial-tracking", High, Current),
];

/// Looks a feature up by its exact (lowercase) name.
#[must_use]
pub fn feature(name: &str) -> Option<&'static Feature> {
    FEATURES
        .binary_search_by(|f| f.name.cmp(name))
        .ok()
        .and_then(|i| FEATURES.get(i))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_is_sorted_and_unique() {
        assert!(FEATURES.windows(2).all(|w| w[0].name < w[1].name));
        assert!(FEATURES.iter().all(|f| crate::sf::is_key(f.name)));
    }

    #[test]
    fn lookups() {
        assert_eq!(feature("camera").map(|f| f.sensitivity), Some(High));
        assert_eq!(
            feature("interest-cohort").map(|f| f.status),
            Some(Deprecated)
        );
        assert_eq!(feature("Camera"), None);
        assert_eq!(feature("nope"), None);
    }
}

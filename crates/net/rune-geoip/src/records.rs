//! Typed views of the common record shapes (GeoIP2/GeoLite2 and the
//! DB-IP "compat" databases share them).
//!
//! Each `from_value` is lenient: a missing field, or one of an unexpected
//! type, is left empty instead of failing the whole record.

use std::collections::BTreeMap;

use crate::value::Value;

/// Localized names by locale code (`en`, `de`, `pt-BR`, ...).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Names(pub BTreeMap<String, String>);

impl Names {
    fn from_value(value: Option<&Value>) -> Self {
        Self(
            value
                .and_then(Value::as_map)
                .map(|map| {
                    map.iter()
                        .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_owned())))
                        .collect()
                })
                .unwrap_or_default(),
        )
    }

    /// The name in `locale`.
    #[must_use]
    pub fn get(&self, locale: &str) -> Option<&str> {
        self.0.get(locale).map(String::as_str)
    }

    /// The name in the first of `locales` that has one.
    #[must_use]
    pub fn preferred(&self, locales: &[&str]) -> Option<&str> {
        locales.iter().find_map(|locale| self.get(locale))
    }

    /// The English name.
    #[must_use]
    pub fn en(&self) -> Option<&str> {
        self.get("en")
    }

    /// Whether there are no names.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

fn string(value: &Value, key: &str) -> Option<String> {
    value.get(key)?.as_str().map(str::to_owned)
}

fn u32_field(value: &Value, key: &str) -> Option<u32> {
    value.get(key)?.as_u64().and_then(|n| u32::try_from(n).ok())
}

fn flag(value: &Value, key: &str) -> bool {
    value.get(key).and_then(Value::as_bool).unwrap_or(false)
}

/// A continent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Continent {
    /// Two-letter code (`EU`, `NA`, ...).
    pub code: Option<String>,
    /// `GeoNames` identifier.
    pub geoname_id: Option<u32>,
    /// Localized names.
    pub names: Names,
}

impl Continent {
    fn from_value(value: &Value) -> Self {
        Self {
            code: string(value, "code"),
            geoname_id: u32_field(value, "geoname_id"),
            names: Names::from_value(value.get("names")),
        }
    }
}

/// A country (the located, registered or represented country).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Country {
    /// ISO 3166-1 alpha-2 code.
    pub iso_code: Option<String>,
    /// `GeoNames` identifier.
    pub geoname_id: Option<u32>,
    /// Whether the country is a member state of the European Union.
    pub is_in_european_union: bool,
    /// Localized names.
    pub names: Names,
}

impl Country {
    fn from_value(value: &Value) -> Self {
        Self {
            iso_code: string(value, "iso_code"),
            geoname_id: u32_field(value, "geoname_id"),
            is_in_european_union: flag(value, "is_in_european_union"),
            names: Names::from_value(value.get("names")),
        }
    }
}

/// A subdivision (state, province, region), largest first in
/// [`CityRecord::subdivisions`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Subdivision {
    /// ISO 3166-2 subdivision code, without the country prefix.
    pub iso_code: Option<String>,
    /// `GeoNames` identifier.
    pub geoname_id: Option<u32>,
    /// Localized names.
    pub names: Names,
}

/// A city.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct City {
    /// `GeoNames` identifier.
    pub geoname_id: Option<u32>,
    /// Localized names.
    pub names: Names,
}

/// Approximate coordinates.
#[derive(Debug, Clone, Default, PartialEq)]
#[non_exhaustive]
pub struct Location {
    /// Latitude in degrees.
    pub latitude: Option<f64>,
    /// Longitude in degrees.
    pub longitude: Option<f64>,
    /// Radius in kilometres around the coordinates that likely contains
    /// the address.
    pub accuracy_radius: Option<u16>,
    /// IANA time zone, such as `Europe/Berlin`.
    pub time_zone: Option<String>,
    /// US metro code (deprecated by `MaxMind`).
    pub metro_code: Option<u16>,
}

/// Network flags from the `traits` map.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Traits {
    /// The network is anycast.
    pub is_anycast: bool,
    /// The address belongs to an anonymous proxy (deprecated by `MaxMind`).
    pub is_anonymous_proxy: bool,
    /// The address belongs to a satellite provider (deprecated by `MaxMind`).
    pub is_satellite_provider: bool,
}

impl Traits {
    fn from_value(value: &Value) -> Self {
        Self {
            is_anycast: flag(value, "is_anycast"),
            is_anonymous_proxy: flag(value, "is_anonymous_proxy"),
            is_satellite_provider: flag(value, "is_satellite_provider"),
        }
    }
}

/// A Country database record (`GeoLite2-Country`, `GeoIP2-Country`,
/// `dbip-country-lite`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct CountryRecord {
    /// Continent of the located country.
    pub continent: Continent,
    /// Country the address is located in.
    pub country: Country,
    /// Country the network is registered in (by the RIR).
    pub registered_country: Country,
    /// Country represented by users of the address (military bases,
    /// embassies), when it differs.
    pub represented_country: Option<Country>,
    /// Network flags.
    pub traits: Traits,
}

impl CountryRecord {
    /// Reads the record from a decoded value.
    #[must_use]
    pub fn from_value(value: &Value) -> Self {
        let part = |key| value.get(key).unwrap_or(&Value::Bool(false));
        Self {
            continent: Continent::from_value(part("continent")),
            country: Country::from_value(part("country")),
            registered_country: Country::from_value(part("registered_country")),
            represented_country: value.get("represented_country").map(Country::from_value),
            traits: Traits::from_value(part("traits")),
        }
    }
}

/// A City database record (`GeoLite2-City`, `GeoIP2-City`,
/// `dbip-city-lite`): the country fields plus city, subdivisions, postal
/// code and location.
#[derive(Debug, Clone, Default, PartialEq)]
#[non_exhaustive]
pub struct CityRecord {
    /// Continent of the located country.
    pub continent: Continent,
    /// Country the address is located in.
    pub country: Country,
    /// Country the network is registered in (by the RIR).
    pub registered_country: Country,
    /// Country represented by users of the address, when it differs.
    pub represented_country: Option<Country>,
    /// Network flags.
    pub traits: Traits,
    /// The city.
    pub city: City,
    /// Subdivisions, largest first.
    pub subdivisions: Vec<Subdivision>,
    /// Postal code.
    pub postal_code: Option<String>,
    /// Coordinates and time zone.
    pub location: Location,
}

impl CityRecord {
    /// Reads the record from a decoded value.
    #[must_use]
    pub fn from_value(value: &Value) -> Self {
        let none = Value::Bool(false);
        let city = value.get("city").unwrap_or(&none);
        let location = value.get("location").unwrap_or(&none);
        let u16_field = |key| {
            location
                .get(key)
                .and_then(Value::as_u64)
                .and_then(|n| u16::try_from(n).ok())
        };
        let CountryRecord {
            continent,
            country,
            registered_country,
            represented_country,
            traits,
        } = CountryRecord::from_value(value);
        Self {
            continent,
            country,
            registered_country,
            represented_country,
            traits,
            city: City {
                geoname_id: u32_field(city, "geoname_id"),
                names: Names::from_value(city.get("names")),
            },
            subdivisions: value
                .get("subdivisions")
                .and_then(Value::as_array)
                .unwrap_or_default()
                .iter()
                .map(|s| Subdivision {
                    iso_code: string(s, "iso_code"),
                    geoname_id: u32_field(s, "geoname_id"),
                    names: Names::from_value(s.get("names")),
                })
                .collect(),
            postal_code: value.get("postal").and_then(|p| string(p, "code")),
            location: Location {
                latitude: location.get("latitude").and_then(Value::as_f64),
                longitude: location.get("longitude").and_then(Value::as_f64),
                accuracy_radius: u16_field("accuracy_radius"),
                time_zone: string(location, "time_zone"),
                metro_code: u16_field("metro_code"),
            },
        }
    }
}

/// An ASN database record (`GeoLite2-ASN`, `dbip-asn-lite`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct AsnRecord {
    /// Autonomous system number.
    pub autonomous_system_number: Option<u32>,
    /// Organization that holds the AS.
    pub autonomous_system_organization: Option<String>,
}

impl AsnRecord {
    /// Reads the record from a decoded value.
    #[must_use]
    pub fn from_value(value: &Value) -> Self {
        Self {
            autonomous_system_number: u32_field(value, "autonomous_system_number"),
            autonomous_system_organization: string(value, "autonomous_system_organization"),
        }
    }
}

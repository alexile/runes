//! Typed RDAP response objects
//! ([RFC 9083](https://www.rfc-editor.org/rfc/rfc9083)).
//!
//! Every field is optional or defaults to empty, and unknown members are
//! ignored, so the models accept the many server dialects in the wild.
//! Dates are kept as the RFC 3339 strings the server sent.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer};

use crate::vcard::Contact;

macro_rules! string_enum {
    (
        $(#[$meta:meta])*
        $name:ident { $( $(#[$vmeta:meta])* $variant:ident = $text:literal, )* }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        #[non_exhaustive]
        pub enum $name {
            $( $(#[$vmeta])* $variant, )*
            /// A value this crate does not know, lower-cased.
            Other(String),
        }

        impl $name {
            /// The registered (lower-case) text of this value.
            #[must_use]
            pub fn as_str(&self) -> &str {
                match self {
                    $( Self::$variant => $text, )*
                    Self::Other(s) => s,
                }
            }
        }

        impl FromStr for $name {
            type Err = std::convert::Infallible;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let lower = s.trim().to_ascii_lowercase();
                Ok(match lower.as_str() {
                    $( $text => Self::$variant, )*
                    _ => Self::Other(lower),
                })
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = String::deserialize(d)?;
                let Ok(v) = s.parse();
                Ok(v)
            }
        }
    };
}

string_enum! {
    /// An object status
    /// ([RFC 9083 §4.6](https://www.rfc-editor.org/rfc/rfc9083#section-4.6),
    /// the IANA "RDAP JSON Values" registry, including the EPP mappings of
    /// [RFC 8056](https://www.rfc-editor.org/rfc/rfc8056)).
    Status {
        /// `validated`
        Validated = "validated",
        /// `renew prohibited`
        RenewProhibited = "renew prohibited",
        /// `update prohibited`
        UpdateProhibited = "update prohibited",
        /// `transfer prohibited`
        TransferProhibited = "transfer prohibited",
        /// `delete prohibited`
        DeleteProhibited = "delete prohibited",
        /// `proxy`
        Proxy = "proxy",
        /// `private`
        Private = "private",
        /// `removed`
        Removed = "removed",
        /// `obscured`
        Obscured = "obscured",
        /// `associated`
        Associated = "associated",
        /// `active`
        Active = "active",
        /// `inactive`
        Inactive = "inactive",
        /// `locked`
        Locked = "locked",
        /// `pending create`
        PendingCreate = "pending create",
        /// `pending renew`
        PendingRenew = "pending renew",
        /// `pending transfer`
        PendingTransfer = "pending transfer",
        /// `pending update`
        PendingUpdate = "pending update",
        /// `pending delete`
        PendingDelete = "pending delete",
        /// `pending restore`
        PendingRestore = "pending restore",
        /// `add period`
        AddPeriod = "add period",
        /// `auto renew period`
        AutoRenewPeriod = "auto renew period",
        /// `renew period`
        RenewPeriod = "renew period",
        /// `transfer period`
        TransferPeriod = "transfer period",
        /// `redemption period`
        RedemptionPeriod = "redemption period",
        /// `client delete prohibited`
        ClientDeleteProhibited = "client delete prohibited",
        /// `client hold`
        ClientHold = "client hold",
        /// `client renew prohibited`
        ClientRenewProhibited = "client renew prohibited",
        /// `client transfer prohibited`
        ClientTransferProhibited = "client transfer prohibited",
        /// `client update prohibited`
        ClientUpdateProhibited = "client update prohibited",
        /// `server delete prohibited`
        ServerDeleteProhibited = "server delete prohibited",
        /// `server hold`
        ServerHold = "server hold",
        /// `server renew prohibited`
        ServerRenewProhibited = "server renew prohibited",
        /// `server transfer prohibited`
        ServerTransferProhibited = "server transfer prohibited",
        /// `server update prohibited`
        ServerUpdateProhibited = "server update prohibited",
        /// `reserved` (RIR profiles)
        Reserved = "reserved",
    }
}

string_enum! {
    /// The role an entity plays for the object it is attached to
    /// ([RFC 9083 §10.2.4](https://www.rfc-editor.org/rfc/rfc9083#section-10.2.4)).
    Role {
        /// `registrant`
        Registrant = "registrant",
        /// `technical`
        Technical = "technical",
        /// `administrative`
        Administrative = "administrative",
        /// `abuse`
        Abuse = "abuse",
        /// `billing`
        Billing = "billing",
        /// `registrar`
        Registrar = "registrar",
        /// `reseller`
        Reseller = "reseller",
        /// `sponsor`
        Sponsor = "sponsor",
        /// `proxy`
        Proxy = "proxy",
        /// `notifications`
        Notifications = "notifications",
        /// `noc`
        Noc = "noc",
    }
}

string_enum! {
    /// What an [`Event`] records
    /// ([RFC 9083 §10.2.3](https://www.rfc-editor.org/rfc/rfc9083#section-10.2.3)).
    EventAction {
        /// `registration`
        Registration = "registration",
        /// `reregistration`
        Reregistration = "reregistration",
        /// `last changed`
        LastChanged = "last changed",
        /// `expiration`
        Expiration = "expiration",
        /// `deletion`
        Deletion = "deletion",
        /// `reinstantiation`
        Reinstantiation = "reinstantiation",
        /// `transfer`
        Transfer = "transfer",
        /// `locked`
        Locked = "locked",
        /// `unlocked`
        Unlocked = "unlocked",
        /// `last update of RDAP database`
        LastUpdateOfRdapDatabase = "last update of rdap database",
        /// `registrar expiration`
        RegistrarExpiration = "registrar expiration",
    }
}

/// A link ([RFC 9083 §4.2](https://www.rfc-editor.org/rfc/rfc9083#section-4.2)).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct Link {
    /// The context URI.
    pub value: Option<String>,
    /// The relation type (`self`, `related`, `alternate`, …).
    pub rel: Option<String>,
    /// The target URI.
    pub href: Option<String>,
    /// The target's media type.
    #[serde(rename = "type")]
    pub media_type: Option<String>,
    /// The target's title.
    pub title: Option<String>,
}

/// A notice or remark ([RFC 9083 §4.3](https://www.rfc-editor.org/rfc/rfc9083#section-4.3)).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct Notice {
    /// The title.
    pub title: Option<String>,
    /// The type (e.g. `result set truncated due to authorization`).
    #[serde(rename = "type")]
    pub kind: Option<String>,
    /// The text, one string per paragraph.
    #[serde(deserialize_with = "lenient_strings")]
    pub description: Vec<String>,
    /// Related links.
    #[serde(deserialize_with = "lenient_vec")]
    pub links: Vec<Link>,
}

/// An event ([RFC 9083 §4.5](https://www.rfc-editor.org/rfc/rfc9083#section-4.5)).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[non_exhaustive]
pub struct Event {
    /// What happened.
    #[serde(rename = "eventAction")]
    pub action: EventAction,
    /// When (RFC 3339), as sent.
    #[serde(rename = "eventDate", default)]
    pub date: Option<String>,
    /// Who did it, as a handle.
    #[serde(rename = "eventActor", default)]
    pub actor: Option<String>,
}

/// A public identifier such as an IANA registrar ID
/// ([RFC 9083 §4.8](https://www.rfc-editor.org/rfc/rfc9083#section-4.8)).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct PublicId {
    /// The identifier's type, e.g. `IANA Registrar ID`.
    #[serde(rename = "type")]
    pub kind: String,
    /// The identifier.
    pub identifier: String,
}

/// An entity: a person or organisation
/// ([RFC 9083 §5.1](https://www.rfc-editor.org/rfc/rfc9083#section-5.1)).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, rename_all = "camelCase")]
#[non_exhaustive]
pub struct Entity {
    /// The registry handle.
    pub handle: Option<String>,
    /// Contact details from the jCard `vcardArray`.
    #[serde(rename = "vcardArray", deserialize_with = "lenient_contact")]
    pub contact: Option<Contact>,
    /// The roles this entity plays for its parent object.
    #[serde(deserialize_with = "lenient_vec")]
    pub roles: Vec<Role>,
    /// Public identifiers (e.g. the IANA registrar ID).
    #[serde(deserialize_with = "lenient_vec")]
    pub public_ids: Vec<PublicId>,
    /// Nested entities (e.g. a registrar's abuse contact).
    #[serde(deserialize_with = "lenient_vec")]
    pub entities: Vec<Self>,
    /// Status values.
    #[serde(deserialize_with = "lenient_vec")]
    pub status: Vec<Status>,
    /// Events.
    #[serde(deserialize_with = "lenient_vec")]
    pub events: Vec<Event>,
    /// Links.
    #[serde(deserialize_with = "lenient_vec")]
    pub links: Vec<Link>,
    /// Remarks.
    #[serde(deserialize_with = "lenient_vec")]
    pub remarks: Vec<Notice>,
    /// The WHOIS server for this object.
    pub port43: Option<String>,
}

/// A nameserver's addresses.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct IpAddresses {
    /// IPv4 addresses, as sent.
    #[serde(deserialize_with = "lenient_strings")]
    pub v4: Vec<String>,
    /// IPv6 addresses, as sent.
    #[serde(deserialize_with = "lenient_strings")]
    pub v6: Vec<String>,
}

/// A nameserver ([RFC 9083 §5.2](https://www.rfc-editor.org/rfc/rfc9083#section-5.2)).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, rename_all = "camelCase")]
#[non_exhaustive]
pub struct Nameserver {
    /// The registry handle.
    pub handle: Option<String>,
    /// The host name in LDH (A-label) form.
    pub ldh_name: Option<String>,
    /// The host name in Unicode form.
    pub unicode_name: Option<String>,
    /// Glue addresses.
    pub ip_addresses: Option<IpAddresses>,
    /// Entities.
    #[serde(deserialize_with = "lenient_vec")]
    pub entities: Vec<Entity>,
    /// Status values.
    #[serde(deserialize_with = "lenient_vec")]
    pub status: Vec<Status>,
    /// Events.
    #[serde(deserialize_with = "lenient_vec")]
    pub events: Vec<Event>,
    /// Links.
    #[serde(deserialize_with = "lenient_vec")]
    pub links: Vec<Link>,
    /// Remarks.
    #[serde(deserialize_with = "lenient_vec")]
    pub remarks: Vec<Notice>,
    /// The WHOIS server for this object.
    pub port43: Option<String>,
}

impl Nameserver {
    /// The host name: `ldhName`, else `unicodeName`.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.ldh_name.as_deref().or(self.unicode_name.as_deref())
    }
}

/// A DS record ([RFC 9083 §5.3](https://www.rfc-editor.org/rfc/rfc9083#section-5.3)).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, rename_all = "camelCase")]
#[non_exhaustive]
pub struct DsData {
    /// Key tag.
    pub key_tag: Option<u32>,
    /// DNSSEC algorithm number.
    pub algorithm: Option<u8>,
    /// Digest type number.
    pub digest_type: Option<u8>,
    /// Hex digest.
    pub digest: Option<String>,
}

/// DNSSEC delegation information.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, rename_all = "camelCase")]
#[non_exhaustive]
pub struct SecureDns {
    /// Whether the zone is signed.
    pub zone_signed: Option<bool>,
    /// Whether the delegation is signed (DS present in the parent).
    pub delegation_signed: Option<bool>,
    /// DS records.
    #[serde(deserialize_with = "lenient_vec")]
    pub ds_data: Vec<DsData>,
}

/// A domain ([RFC 9083 §5.3](https://www.rfc-editor.org/rfc/rfc9083#section-5.3)).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, rename_all = "camelCase")]
#[non_exhaustive]
pub struct Domain {
    /// The registry handle.
    pub handle: Option<String>,
    /// The name in LDH (A-label) form.
    pub ldh_name: Option<String>,
    /// The name in Unicode form.
    pub unicode_name: Option<String>,
    /// Delegated nameservers.
    #[serde(deserialize_with = "lenient_vec")]
    pub nameservers: Vec<Nameserver>,
    /// DNSSEC information.
    #[serde(rename = "secureDNS")]
    pub secure_dns: Option<SecureDns>,
    /// Entities: registrar, registrant, contacts.
    #[serde(deserialize_with = "lenient_vec")]
    pub entities: Vec<Entity>,
    /// Status values.
    #[serde(deserialize_with = "lenient_vec")]
    pub status: Vec<Status>,
    /// Public identifiers.
    #[serde(deserialize_with = "lenient_vec")]
    pub public_ids: Vec<PublicId>,
    /// Events: registration, expiration, last changed, …
    #[serde(deserialize_with = "lenient_vec")]
    pub events: Vec<Event>,
    /// Links.
    #[serde(deserialize_with = "lenient_vec")]
    pub links: Vec<Link>,
    /// Remarks.
    #[serde(deserialize_with = "lenient_vec")]
    pub remarks: Vec<Notice>,
    /// Response notices (terms of service, …).
    #[serde(deserialize_with = "lenient_vec")]
    pub notices: Vec<Notice>,
    /// The WHOIS server for this object.
    pub port43: Option<String>,
}

impl Domain {
    /// The domain name: `ldhName`, else `unicodeName`.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.ldh_name.as_deref().or(self.unicode_name.as_deref())
    }

    /// The nameserver host names.
    pub fn nameserver_names(&self) -> impl Iterator<Item = &str> {
        self.nameservers.iter().filter_map(Nameserver::name)
    }

    /// The registrar entity.
    #[must_use]
    pub fn registrar(&self) -> Option<&Entity> {
        self.entity_with_role(&Role::Registrar)
    }

    /// The registrar's name (its jCard `fn`).
    #[must_use]
    pub fn registrar_name(&self) -> Option<&str> {
        self.registrar()?.contact.as_ref()?.name.as_deref()
    }

    /// The registrar's IANA ID, from its public IDs (or its handle, which
    /// gTLD registries set to the same number).
    #[must_use]
    pub fn registrar_iana_id(&self) -> Option<&str> {
        let registrar = self.registrar()?;
        registrar
            .public_ids
            .iter()
            .find(|p| p.kind.eq_ignore_ascii_case("IANA Registrar ID"))
            .map(|p| p.identifier.as_str())
    }
}

/// A CIDR block from the `cidr0` extension.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Cidr {
    /// The network address, as sent.
    pub prefix: String,
    /// The prefix length.
    pub length: u8,
}

impl<'de> Deserialize<'de> for Cidr {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            v4prefix: Option<String>,
            v6prefix: Option<String>,
            length: u8,
        }
        let raw = Raw::deserialize(d)?;
        let prefix = raw
            .v4prefix
            .or(raw.v6prefix)
            .ok_or_else(|| serde::de::Error::missing_field("v4prefix"))?;
        Ok(Self {
            prefix,
            length: raw.length,
        })
    }
}

/// An IP network ([RFC 9083 §5.4](https://www.rfc-editor.org/rfc/rfc9083#section-5.4)).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, rename_all = "camelCase")]
#[non_exhaustive]
pub struct IpNetwork {
    /// The registry handle.
    pub handle: Option<String>,
    /// First address of the block.
    pub start_address: Option<String>,
    /// Last address of the block.
    pub end_address: Option<String>,
    /// `v4` or `v6`.
    pub ip_version: Option<String>,
    /// The network name.
    pub name: Option<String>,
    /// The allocation type (RIR specific, e.g. `DIRECT ALLOCATION`).
    #[serde(rename = "type")]
    pub kind: Option<String>,
    /// ISO 3166 country code.
    pub country: Option<String>,
    /// The handle of the enclosing network.
    pub parent_handle: Option<String>,
    /// The block as CIDR prefixes (`cidr0` extension).
    #[serde(rename = "cidr0_cidrs", deserialize_with = "lenient_vec")]
    pub cidrs: Vec<Cidr>,
    /// Entities: registrant, abuse, technical contacts.
    #[serde(deserialize_with = "lenient_vec")]
    pub entities: Vec<Entity>,
    /// Status values.
    #[serde(deserialize_with = "lenient_vec")]
    pub status: Vec<Status>,
    /// Events.
    #[serde(deserialize_with = "lenient_vec")]
    pub events: Vec<Event>,
    /// Links.
    #[serde(deserialize_with = "lenient_vec")]
    pub links: Vec<Link>,
    /// Remarks.
    #[serde(deserialize_with = "lenient_vec")]
    pub remarks: Vec<Notice>,
    /// Response notices.
    #[serde(deserialize_with = "lenient_vec")]
    pub notices: Vec<Notice>,
    /// The WHOIS server for this object.
    pub port43: Option<String>,
}

/// An autonomous system number range
/// ([RFC 9083 §5.5](https://www.rfc-editor.org/rfc/rfc9083#section-5.5)).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, rename_all = "camelCase")]
#[non_exhaustive]
pub struct Autnum {
    /// The registry handle (e.g. `AS15169`).
    pub handle: Option<String>,
    /// First ASN of the range.
    pub start_autnum: Option<u32>,
    /// Last ASN of the range.
    pub end_autnum: Option<u32>,
    /// The AS name.
    pub name: Option<String>,
    /// The allocation type.
    #[serde(rename = "type")]
    pub kind: Option<String>,
    /// ISO 3166 country code.
    pub country: Option<String>,
    /// Entities.
    #[serde(deserialize_with = "lenient_vec")]
    pub entities: Vec<Entity>,
    /// Status values.
    #[serde(deserialize_with = "lenient_vec")]
    pub status: Vec<Status>,
    /// Events.
    #[serde(deserialize_with = "lenient_vec")]
    pub events: Vec<Event>,
    /// Links.
    #[serde(deserialize_with = "lenient_vec")]
    pub links: Vec<Link>,
    /// Remarks.
    #[serde(deserialize_with = "lenient_vec")]
    pub remarks: Vec<Notice>,
    /// Response notices.
    #[serde(deserialize_with = "lenient_vec")]
    pub notices: Vec<Notice>,
    /// The WHOIS server for this object.
    pub port43: Option<String>,
}

/// Accessors shared by every object class.
macro_rules! common_accessors {
    ($($ty:ty),*) => {$(
        impl $ty {
            /// The date of the first event with `action`.
            #[must_use]
            pub fn event_date(&self, action: &EventAction) -> Option<&str> {
                self.events
                    .iter()
                    .find(|e| &e.action == action)
                    .and_then(|e| e.date.as_deref())
            }

            /// The `registration` date.
            #[must_use]
            pub fn registration(&self) -> Option<&str> {
                self.event_date(&EventAction::Registration)
            }

            /// The `expiration` date.
            #[must_use]
            pub fn expiration(&self) -> Option<&str> {
                self.event_date(&EventAction::Expiration)
            }

            /// The `last changed` date.
            #[must_use]
            pub fn last_changed(&self) -> Option<&str> {
                self.event_date(&EventAction::LastChanged)
            }

            /// Whether `status` contains `s`.
            #[must_use]
            pub fn has_status(&self, s: &Status) -> bool {
                self.status.contains(s)
            }

            /// The first entity with `role`, searching nested entities
            /// breadth-first.
            #[must_use]
            pub fn entity_with_role(&self, role: &Role) -> Option<&Entity> {
                find_role(&self.entities, role)
            }

            /// The abuse contact's first e-mail address.
            #[must_use]
            pub fn abuse_email(&self) -> Option<&str> {
                find_role(&self.entities, &Role::Abuse)?
                    .contact
                    .as_ref()?
                    .emails
                    .first()
                    .map(String::as_str)
            }

            /// Every entity, nested ones included, depth-first.
            #[must_use]
            pub fn all_entities(&self) -> Vec<&Entity> {
                let mut out = Vec::new();
                collect(&self.entities, &mut out);
                out
            }
        }
    )*};
}

common_accessors!(Domain, IpNetwork, Autnum, Nameserver, Entity);

/// Nesting deeper than this is not searched (serde already caps JSON depth;
/// this bounds the work on wide, deep trees).
const MAX_ENTITY_DEPTH: usize = 16;

fn find_role<'a>(entities: &'a [Entity], role: &Role) -> Option<&'a Entity> {
    let mut level: Vec<&Entity> = entities.iter().collect();
    for _ in 0..MAX_ENTITY_DEPTH {
        if let Some(hit) = level.iter().find(|e| e.roles.contains(role)) {
            return Some(hit);
        }
        level = level.iter().flat_map(|e| e.entities.iter()).collect();
        if level.is_empty() {
            break;
        }
    }
    None
}

fn collect<'a>(entities: &'a [Entity], out: &mut Vec<&'a Entity>) {
    fn walk<'a>(entities: &'a [Entity], out: &mut Vec<&'a Entity>, depth: usize) {
        if depth >= MAX_ENTITY_DEPTH {
            return;
        }
        for e in entities {
            out.push(e);
            walk(&e.entities, out, depth + 1);
        }
    }
    walk(entities, out, 0);
}

/// A server's RDAP error response
/// ([RFC 9083 §6](https://www.rfc-editor.org/rfc/rfc9083#section-6)).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, rename_all = "camelCase")]
#[non_exhaustive]
pub struct ErrorResponse {
    /// The error code (normally the HTTP status).
    pub error_code: Option<u16>,
    /// A short title.
    pub title: Option<String>,
    /// Explanation lines.
    #[serde(deserialize_with = "lenient_strings")]
    pub description: Vec<String>,
}

/// One RDAP object, by its `objectClassName`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Object {
    /// `domain`
    Domain(Box<Domain>),
    /// `ip network`
    IpNetwork(Box<IpNetwork>),
    /// `autnum`
    Autnum(Box<Autnum>),
    /// `nameserver`
    Nameserver(Box<Nameserver>),
    /// `entity`
    Entity(Box<Entity>),
}

impl Object {
    /// The object's `objectClassName`.
    #[must_use]
    pub const fn class_name(&self) -> &'static str {
        match self {
            Self::Domain(_) => "domain",
            Self::IpNetwork(_) => "ip network",
            Self::Autnum(_) => "autnum",
            Self::Nameserver(_) => "nameserver",
            Self::Entity(_) => "entity",
        }
    }

    /// The object's `handle`.
    #[must_use]
    pub fn handle(&self) -> Option<&str> {
        match self {
            Self::Domain(o) => o.handle.as_deref(),
            Self::IpNetwork(o) => o.handle.as_deref(),
            Self::Autnum(o) => o.handle.as_deref(),
            Self::Nameserver(o) => o.handle.as_deref(),
            Self::Entity(o) => o.handle.as_deref(),
        }
    }

    /// The object's events.
    #[must_use]
    pub fn events(&self) -> &[Event] {
        match self {
            Self::Domain(o) => &o.events,
            Self::IpNetwork(o) => &o.events,
            Self::Autnum(o) => &o.events,
            Self::Nameserver(o) => &o.events,
            Self::Entity(o) => &o.events,
        }
    }

    /// The object's status values.
    #[must_use]
    pub fn status(&self) -> &[Status] {
        match self {
            Self::Domain(o) => &o.status,
            Self::IpNetwork(o) => &o.status,
            Self::Autnum(o) => &o.status,
            Self::Nameserver(o) => &o.status,
            Self::Entity(o) => &o.status,
        }
    }

    /// The object's top-level entities (none for an entity itself: see its
    /// `entities` field).
    #[must_use]
    pub fn entities(&self) -> &[Entity] {
        match self {
            Self::Domain(o) => &o.entities,
            Self::IpNetwork(o) => &o.entities,
            Self::Autnum(o) => &o.entities,
            Self::Nameserver(o) => &o.entities,
            Self::Entity(o) => &o.entities,
        }
    }

    /// The domain, if this is one.
    #[must_use]
    pub fn as_domain(&self) -> Option<&Domain> {
        match self {
            Self::Domain(d) => Some(d),
            _ => None,
        }
    }

    /// The IP network, if this is one.
    #[must_use]
    pub fn as_ip_network(&self) -> Option<&IpNetwork> {
        match self {
            Self::IpNetwork(n) => Some(n),
            _ => None,
        }
    }

    /// The autnum, if this is one.
    #[must_use]
    pub fn as_autnum(&self) -> Option<&Autnum> {
        match self {
            Self::Autnum(a) => Some(a),
            _ => None,
        }
    }

    /// The nameserver, if this is one.
    #[must_use]
    pub fn as_nameserver(&self) -> Option<&Nameserver> {
        match self {
            Self::Nameserver(n) => Some(n),
            _ => None,
        }
    }

    /// The entity, if this is one.
    #[must_use]
    pub fn as_entity(&self) -> Option<&Entity> {
        match self {
            Self::Entity(e) => Some(e),
            _ => None,
        }
    }
}

/// A list that tolerates a missing value, `null`, a single item, and items
/// of the wrong shape (which are skipped).
fn lenient_vec<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: serde::de::DeserializeOwned,
{
    let value = serde_json::Value::deserialize(d)?;
    Ok(match value {
        serde_json::Value::Array(items) => items
            .into_iter()
            .filter_map(|v| serde_json::from_value(v).ok())
            .collect(),
        serde_json::Value::Null => Vec::new(),
        other => serde_json::from_value(other).ok().into_iter().collect(),
    })
}

/// Like [`lenient_vec`] for strings; a bare string becomes one item.
fn lenient_strings<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    lenient_vec(d)
}

fn lenient_contact<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Contact>, D::Error> {
    let value = serde_json::Value::deserialize(d)?;
    Ok(Contact::from_jcard(&value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_enums() {
        assert_eq!("Client Hold".parse::<Status>().unwrap(), Status::ClientHold);
        assert_eq!(
            "Shiny New".parse::<Status>().unwrap(),
            Status::Other("shiny new".into())
        );
        assert_eq!(Role::Registrar.to_string(), "registrar");
        assert_eq!(
            "last update of RDAP database"
                .parse::<EventAction>()
                .unwrap(),
            EventAction::LastUpdateOfRdapDatabase
        );
    }

    #[test]
    fn lenient_lists() {
        let d: Domain = serde_json::from_str(
            r#"{"status":"active","events":[{"eventAction":"registration","eventDate":"2000-01-01T00:00:00Z"},42,{"bad":1}],
                "nameservers":null,"entities":[{"roles":["Registrar"],"vcardArray":"nonsense"}]}"#,
        )
        .unwrap();
        assert_eq!(d.status, [Status::Active]);
        assert_eq!(d.registration(), Some("2000-01-01T00:00:00Z"));
        assert_eq!(d.nameservers.len(), 0);
        assert!(d.registrar().unwrap().contact.is_none());
    }

    #[test]
    fn nested_role_search() {
        let n: IpNetwork = serde_json::from_str(
            r#"{"entities":[{"handle":"ORG","roles":["registrant"],"entities":[
                {"handle":"AB","roles":["abuse"],"vcardArray":["vcard",[["email",{},"text","abuse@example.net"]]]}]}]}"#,
        )
        .unwrap();
        assert_eq!(n.abuse_email(), Some("abuse@example.net"));
        assert_eq!(n.all_entities().len(), 2);
        assert!(n.entity_with_role(&Role::Billing).is_none());
    }
}

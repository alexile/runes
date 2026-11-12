# rune-wsdl

> WSDL 1.1 / 2.0 import: SOAP 1.1 / 1.2 operations, message parts, inline XSD expanded into sample envelopes, HttpRequests and insertion points

[![crates.io](https://img.shields.io/crates/v/rune-wsdl)](https://crates.io/crates/rune-wsdl)
[![docs.rs](https://img.shields.io/docsrs/rune-wsdl)](https://docs.rs/rune-wsdl)
[![license](https://img.shields.io/crates/l/rune-wsdl)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

Turns a SOAP service description into requests a scanner or fuzzer can
drive. [WSDL 1.1](https://www.w3.org/TR/2001/NOTE-wsdl-20010315) and
[WSDL 2.0](https://www.w3.org/TR/wsdl20/) documents normalize to one
model:

- **`SoapOperation`**: one per SOAP binding operation exposed by a
  service port / endpoint (or per SOAP binding when there is no service),
  with its service, port, binding, port type / interface, SOAP version,
  `document` / `rpc` style, `literal` / `encoded` use, `SOAPAction`,
  address, documentation, input / output `MessagePart`s and fault names.
- **Sample messages** built from the inline XSD: named and anonymous types,
  `sequence`, `all` and the first `choice` branch, model and attribute
  groups, simple and complex content derivation, `elementFormDefault` /
  `form` qualification, enumerations and lower-bound facets. RPC bodies get
  the operation wrapper and part accessors; `soap:header` blocks are
  included. Recursive types, depth and node count are cut off with a
  warning.
- The serialized **envelope** and an example `POST` **`HttpRequest`** from
  [`rune-http-model`](../rune-http-model): `text/xml` plus `SOAPAction` for
  SOAP 1.1, `application/soap+xml; action=…` for SOAP 1.2.
- **`InsertionPoint`**s: every element text (`/Body/GetQuote/symbol`),
  attribute (`/Header/Auth/@realm`) and the `SOAPAction` header, each with
  its XSD type, value category, `required` / `nillable` / `repeated` and
  enumeration. `SoapOperation::envelope_with` fills them, escaped.

The crate is sans-I/O. `wsdl:import` and `xsd:import` / `include` with a
location are never fetched; they, non-SOAP (HTTP) bindings and unresolved
references become `WsdlSpec::warnings`. DTDs are skipped and entities are
never expanded, and input size, nesting and element count are bounded, so
hostile documents stay cheap.

## Installation

```toml
[dependencies]
rune-wsdl = "0.1"
```

| Feature | Enables |
| --- | --- |
| `serde` | `Serialize`/`Deserialize` for the model |
| `schemars` | `JsonSchema` for the model (implies `serde`) |

## Usage

```rust
use std::collections::BTreeMap;

use rune_wsdl::{Options, SoapVersion, Url, parse};

let wsdl = br#"
<description xmlns="http://www.w3.org/ns/wsdl" targetNamespace="urn:hotel"
    xmlns:tns="urn:hotel" xmlns:wsoap="http://www.w3.org/ns/wsdl/soap">
  <types>
    <xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema" targetNamespace="urn:hotel">
      <xs:element name="checkAvailability">
        <xs:complexType><xs:sequence>
          <xs:element name="checkInDate" type="xs:date"/>
          <xs:element name="roomType" minOccurs="0">
            <xs:simpleType><xs:restriction base="xs:string">
              <xs:enumeration value="single"/><xs:enumeration value="double"/>
            </xs:restriction></xs:simpleType>
          </xs:element>
        </xs:sequence></xs:complexType>
      </xs:element>
    </xs:schema>
  </types>
  <interface name="Reservation">
    <operation name="opCheckAvailability" pattern="http://www.w3.org/ns/wsdl/in-out">
      <input element="tns:checkAvailability"/>
    </operation>
  </interface>
  <binding name="ReservationSoap" interface="tns:Reservation"
      type="http://www.w3.org/ns/wsdl/soap">
    <operation ref="tns:opCheckAvailability" wsoap:action="urn:hotel#check"/>
  </binding>
  <service name="Hotel" interface="tns:Reservation">
    <endpoint name="main" binding="tns:ReservationSoap" address="https://hotel.example.test/soap"/>
  </service>
</description>"#;

let spec = parse(wsdl, &Options::default())?;
let check = spec.operation("opCheckAvailability").unwrap();
assert_eq!(check.soap_version, SoapVersion::Soap12);
assert_eq!(
    check.request.header("Content-Type"),
    Some("application/soap+xml; charset=utf-8; action=\"urn:hotel#check\"")
);
let room = check.insertion_point("/Body/checkAvailability/roomType").unwrap();
assert_eq!(room.enum_values, ["single", "double"]);
assert!(!room.required);

// Put a payload in, and send it to a lab server instead.
let values = BTreeMap::from([(room.name.clone(), String::from("<script>"))]);
let envelope = check.envelope_with(&values);
assert!(envelope.contains("<roomType>&lt;script&gt;</roomType>"));
let lab = Options::default().with_endpoint(Url::parse("http://127.0.0.1:8080/soap").unwrap());
let request = check.to_request_with_envelope(&envelope, &lab);
assert_eq!(request.url, "http://127.0.0.1:8080/soap");
# Ok::<(), rune_wsdl::WsdlError>(())
```

## Stability

The model structs and enums are `#[non_exhaustive]`: read their fields,
build options with `Options::default().with_*(…)`, and give matches a
wildcard arm.

## License

MIT

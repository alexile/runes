//! WSDL 1.1 / 2.0 import: SOAP 1.1 / 1.2 operations, message parts, inline
//! XSD expanded into sample envelopes, [`HttpRequest`]s and insertion
//! points.
//!
//! [`parse`] reads a service description and returns a [`WsdlSpec`] with
//! one [`SoapOperation`] per SOAP binding operation exposed by a service:
//!
//! - the service, port, binding and port type / interface it came from,
//!   the SOAP version, style (`document` / `rpc`), use (`literal` /
//!   `encoded`), `SOAPAction` and endpoint address;
//! - its input and output [`MessagePart`]s and fault names;
//! - sample header blocks and body built from the inline XSD (named and
//!   anonymous types, `sequence` / `all` / first `choice` branch, groups,
//!   attributes, simple and complex content derivation, enumerations and
//!   lower-bound facets), with recursion, depth and size cut off;
//! - the serialized envelope and an example `POST` [`HttpRequest`] (from
//!   `rune-http-model`) with the right `Content-Type` / `SOAPAction`;
//! - [`InsertionPoint`]s: every element text, attribute and the
//!   `SOAPAction` header, each with its XSD type, so payload generators
//!   stay type-aware. [`SoapOperation::envelope_with`] fills them.
//!
//! The crate is sans-I/O: `wsdl:import` and `xsd:import` / `include` with a
//! location are never fetched. They, and other problems inside a readable
//! document, become [`WsdlSpec::warnings`]. Document type declarations are
//! skipped, so entity expansion and external entities cannot be triggered.
//!
//! Specifications: [WSDL 1.1](https://www.w3.org/TR/2001/NOTE-wsdl-20010315),
//! [WSDL 2.0](https://www.w3.org/TR/wsdl20/),
//! [SOAP 1.1](https://www.w3.org/TR/2000/NOTE-SOAP-20000508/) and
//! [SOAP 1.2](https://www.w3.org/TR/soap12-part1/).
//!
//! # Features
//!
//! - `serde`: `Serialize`/`Deserialize` for the model (with
//!   `rune-http-model/serde`).
//! - `schemars`: `JsonSchema` for the model (implies `serde`).
//!
//! # Example
//!
//! ```
//! use std::collections::BTreeMap;
//!
//! use rune_wsdl::{InsertionLocation, Options, SoapVersion, parse};
//!
//! let wsdl = br#"<definitions name="Quotes" targetNamespace="urn:quotes"
//!     xmlns="http://schemas.xmlsoap.org/wsdl/" xmlns:tns="urn:quotes"
//!     xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
//!     xmlns:xs="http://www.w3.org/2001/XMLSchema">
//!   <types>
//!     <xs:schema targetNamespace="urn:quotes" elementFormDefault="qualified">
//!       <xs:element name="GetQuote">
//!         <xs:complexType><xs:sequence>
//!           <xs:element name="symbol" type="xs:string"/>
//!         </xs:sequence></xs:complexType>
//!       </xs:element>
//!     </xs:schema>
//!   </types>
//!   <message name="GetQuoteIn"><part name="body" element="tns:GetQuote"/></message>
//!   <portType name="QuotePort">
//!     <operation name="GetQuote"><input message="tns:GetQuoteIn"/></operation>
//!   </portType>
//!   <binding name="QuoteSoap" type="tns:QuotePort">
//!     <soap:binding transport="http://schemas.xmlsoap.org/soap/http"/>
//!     <operation name="GetQuote">
//!       <soap:operation soapAction="urn:quotes#GetQuote"/>
//!       <input><soap:body use="literal"/></input>
//!     </operation>
//!   </binding>
//!   <service name="QuoteService">
//!     <port name="QuoteSoap" binding="tns:QuoteSoap">
//!       <soap:address location="https://quotes.example.test/soap"/>
//!     </port>
//!   </service>
//! </definitions>"#;
//!
//! let spec = parse(wsdl, &Options::default())?;
//! let quote = spec.operation("GetQuote").unwrap();
//! assert_eq!(quote.soap_version, SoapVersion::Soap11);
//! assert_eq!(quote.request.url, "https://quotes.example.test/soap");
//! assert_eq!(quote.request.header("SOAPAction"), Some("\"urn:quotes#GetQuote\""));
//! assert!(quote.envelope.contains("<ns1:GetQuote><ns1:symbol>string</ns1:symbol></ns1:GetQuote>"));
//!
//! let symbol = quote.insertion_point("/Body/GetQuote/symbol").unwrap();
//! assert_eq!(symbol.location, InsertionLocation::Element);
//! assert_eq!(symbol.xsd_type, "string");
//!
//! let values = BTreeMap::from([(symbol.name.clone(), String::from("' OR 1=1"))]);
//! assert!(quote.envelope_with(&values).contains("<ns1:symbol>&apos; OR 1=1</ns1:symbol>"));
//! # Ok::<(), rune_wsdl::WsdlError>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod error;
mod import;
mod model;
mod render;
mod schema;
mod xml;

pub use error::WsdlError;
pub use import::parse;
pub use model::{
    BodyUse, InsertionLocation, InsertionPoint, MessagePart, OperationStyle, Options,
    SoapOperation, SoapVersion, ValueKind, WsdlSpec, WsdlVersion, XmlAttribute, XmlNode,
};
pub use render::DEFAULT_ENDPOINT;

/// The request type operations are rendered to.
pub use rune_http_model::HttpRequest;
/// The URL type of [`Options::endpoint`].
pub use url::Url;

#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

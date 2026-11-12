//! Imports of public-style WSDL fixtures: the WSDL 1.1 note's `StockQuote`
//! examples (document/literal and RPC/encoded), a two-binding Calculator
//! service and the WSDL 2.0 primer's `GreatH` hotel service. Every generated
//! envelope is checked with an independent namespace-aware XML reader.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test helpers")]

mod common;

use std::collections::BTreeMap;

use common::{read_envelope, text_at};
use rune_wsdl::{
    BodyUse, InsertionLocation, OperationStyle, Options, SoapOperation, SoapVersion, Url,
    ValueKind, WsdlSpec, WsdlVersion, parse,
};

const SOAP11: &str = "http://schemas.xmlsoap.org/soap/envelope/";
const SOAP12: &str = "http://www.w3.org/2003/05/soap-envelope";

fn fixture(name: &str) -> WsdlSpec {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    let bytes = std::fs::read(&path).unwrap_or_else(|error| panic!("{path}: {error}"));
    parse(&bytes, &Options::default()).unwrap_or_else(|error| panic!("{path}: {error}"))
}

/// Every operation's envelope is well-formed, is the request body, and
/// every element insertion point is found in it with its sample value.
fn check_envelopes(spec: &WsdlSpec) {
    for operation in &spec.operations {
        let elements = read_envelope(&operation.envelope);
        let envelope_namespace = match operation.soap_version {
            SoapVersion::Soap11 => SOAP11,
            _ => SOAP12,
        };
        assert_eq!(elements[0].path, "/Envelope");
        assert_eq!(elements[0].namespace.as_deref(), Some(envelope_namespace));
        assert_eq!(operation.request.method, "POST");
        assert_eq!(
            operation.request.body.as_utf8(),
            Some(operation.envelope.as_str())
        );
        for point in &operation.insertion_points {
            if point.location == InsertionLocation::Element && !point.name.contains('[') {
                assert_eq!(
                    text_at(&elements, &format!("/Envelope{}", point.name)),
                    point.value
                );
            }
        }
    }
}

fn operation<'a>(spec: &'a WsdlSpec, name: &str, version: SoapVersion) -> &'a SoapOperation {
    spec.operation_for(name, version)
        .unwrap_or_else(|| panic!("no {name} {version}"))
}

#[test]
fn stockquote_document_literal() {
    let spec = fixture("stockquote-1.1.wsdl");
    check_envelopes(&spec);
    assert_eq!(spec.version, WsdlVersion::Wsdl11);
    assert_eq!(spec.name.as_deref(), Some("StockQuote"));
    assert_eq!(
        spec.target_namespace.as_deref(),
        Some("http://example.com/stockquote.wsdl")
    );
    assert_eq!(spec.services, ["StockQuoteService"]);
    assert!(spec.warnings.is_empty(), "{:?}", spec.warnings);
    assert_eq!(spec.operations.len(), 1);

    let quote = operation(&spec, "GetLastTradePrice", SoapVersion::Soap11);
    assert_eq!(quote.service.as_deref(), Some("StockQuoteService"));
    assert_eq!(quote.port.as_deref(), Some("StockQuotePort"));
    assert_eq!(quote.binding, "StockQuoteSoapBinding");
    assert_eq!(quote.interface.as_deref(), Some("StockQuotePortType"));
    assert_eq!(quote.style, OperationStyle::Document);
    assert_eq!(quote.body_use, BodyUse::Literal);
    assert_eq!(quote.input.len(), 1);
    assert_eq!(
        quote.input[0].element.as_deref(),
        Some("{http://example.com/stockquote.xsd}TradePriceRequest")
    );
    assert_eq!(
        quote.output[0].element.as_deref(),
        Some("{http://example.com/stockquote.xsd}TradePrice")
    );
    assert_eq!(quote.request.url, "http://example.com/stockquote");
    assert_eq!(
        quote.request.header("Content-Type"),
        Some("text/xml; charset=utf-8")
    );
    assert_eq!(
        quote.request.header("SOAPAction"),
        Some("\"http://example.com/GetLastTradePrice\"")
    );

    // No elementFormDefault: the global element is qualified, its child
    // is not.
    let elements = read_envelope(&quote.envelope);
    let request = elements
        .iter()
        .find(|element| element.path == "/Envelope/Body/TradePriceRequest")
        .unwrap();
    assert_eq!(
        request.namespace.as_deref(),
        Some("http://example.com/stockquote.xsd")
    );
    let ticker = elements
        .iter()
        .find(|element| element.path.ends_with("/tickerSymbol"))
        .unwrap();
    assert_eq!(ticker.namespace, None);

    let names: Vec<_> = quote
        .insertion_points
        .iter()
        .map(|point| point.name.as_str())
        .collect();
    assert_eq!(
        names,
        ["/Body/TradePriceRequest/tickerSymbol", "SOAPAction"]
    );
    let action = quote.insertion_point("SOAPAction").unwrap();
    assert_eq!(action.location, InsertionLocation::HttpHeader);
    assert_eq!(action.value, "http://example.com/GetLastTradePrice");
}

#[test]
fn calculator_soap11_and_soap12() {
    let spec = fixture("calculator.wsdl");
    check_envelopes(&spec);
    assert!(spec.warnings.is_empty(), "{:?}", spec.warnings);
    let names: Vec<_> = spec
        .operations
        .iter()
        .map(|operation| format!("{}/{}", operation.name, operation.soap_version))
        .collect();
    assert_eq!(
        names,
        ["Add/soap11", "Divide/soap11", "Add/soap12", "Divide/soap12"]
    );

    let add = operation(&spec, "Add", SoapVersion::Soap11);
    assert_eq!(
        add.documentation.as_deref(),
        Some("Adds two integers. This is a test WebService. ©DNE Online")
    );
    let elements = read_envelope(&add.envelope);
    let int_a = elements
        .iter()
        .find(|element| element.path == "/Envelope/Body/Add/intA")
        .unwrap();
    assert_eq!(int_a.namespace.as_deref(), Some("http://tempuri.org/"));
    assert_eq!(int_a.text, "0");
    let point = add.insertion_point("/Body/Add/intB").unwrap();
    assert_eq!(
        (point.xsd_type.as_str(), point.kind),
        ("int", ValueKind::Integer)
    );
    assert!(point.required && !point.repeated && !point.nillable);

    let add12 = operation(&spec, "Add", SoapVersion::Soap12);
    assert_eq!(add12.port.as_deref(), Some("CalculatorSoap12"));
    assert_eq!(
        add12.request.header("Content-Type"),
        Some("application/soap+xml; charset=utf-8; action=\"http://tempuri.org/Add\"")
    );
    assert_eq!(add12.request.header("SOAPAction"), None);
    assert!(add12.insertion_point("SOAPAction").is_none());
    assert_eq!(
        add12.request.url,
        "http://www.dneonline.com/calculator.asmx"
    );

    // Payloads go in escaped and come back out intact.
    let payload = "1 OR 1=1 <!-- & ]]>";
    let values = BTreeMap::from([(String::from("/Body/Add/intA"), String::from(payload))]);
    let mutated = add.envelope_with(&values);
    let elements = read_envelope(&mutated);
    assert_eq!(text_at(&elements, "/Envelope/Body/Add/intA"), payload);
    assert_eq!(text_at(&elements, "/Envelope/Body/Add/intB"), "0");
    let request = add.to_request_with_envelope(&mutated, &Options::default());
    assert_eq!(request.body.as_utf8(), Some(mutated.as_str()));

    // Endpoint and header overrides.
    let options = Options::default()
        .with_endpoint(Url::parse("http://127.0.0.1:8080/calc").unwrap())
        .with_header("Authorization", "Basic {{credentials}}");
    let request = add.to_request(&options);
    assert_eq!(request.url, "http://127.0.0.1:8080/calc");
    assert_eq!(
        request.header("Authorization"),
        Some("Basic {{credentials}}")
    );
    assert_eq!(request.body.as_utf8(), Some(add.envelope.as_str()));
}

#[test]
fn rpc_encoded_with_header() {
    let spec = fixture("rpc-encoded.wsdl");
    check_envelopes(&spec);
    assert_eq!(
        spec.warnings,
        [
            "schema `common.xsd` is not fetched; types it declares become placeholders",
            "binding `StockQuoteHttpBinding` is not SOAP; skipped",
        ]
    );
    assert_eq!(spec.operations.len(), 1);
    let prices = operation(&spec, "GetTradePrices", SoapVersion::Soap11);
    assert_eq!(prices.style, OperationStyle::Rpc);
    assert_eq!(prices.body_use, BodyUse::Encoded);
    assert_eq!(prices.faults, ["UnknownSymbol"]);
    assert_eq!(
        prices.documentation.as_deref(),
        Some("Prices of a symbol over a period.")
    );
    let inputs: Vec<_> = prices.input.iter().map(|part| part.name.as_str()).collect();
    assert_eq!(inputs, ["tickerSymbol", "exchange", "timePeriod"]);
    assert_eq!(
        prices.input[2].type_name.as_deref(),
        Some("{http://example.com/stockquote.xsd}TimePeriod")
    );
    assert_eq!(
        prices.output[0].type_name.as_deref(),
        Some("{http://schemas.xmlsoap.org/soap/encoding/}Array")
    );

    let elements = read_envelope(&prices.envelope);
    let wrapper = elements
        .iter()
        .find(|element| element.path == "/Envelope/Body/GetTradePrices")
        .unwrap();
    assert_eq!(
        wrapper.namespace.as_deref(),
        Some("http://example.com/stockquote")
    );
    assert!(
        prices
            .envelope
            .contains("soap:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"")
    );
    assert_eq!(
        text_at(
            &elements,
            "/Envelope/Body/GetTradePrices/timePeriod/startTime"
        ),
        "2024-01-01T00:00:00Z"
    );
    let exchange = prices
        .insertion_point("/Body/GetTradePrices/exchange")
        .unwrap();
    assert_eq!(exchange.value, "NYSE");
    assert_eq!(exchange.enum_values, ["NYSE", "NASDAQ"]);

    // The literal header block.
    assert_eq!(prices.header.len(), 1);
    assert_eq!(
        text_at(&elements, "/Envelope/Header/Credentials/user"),
        "string"
    );
    let realm = prices
        .insertion_point("/Header/Credentials/@realm")
        .unwrap();
    assert_eq!(realm.location, InsertionLocation::Attribute);
    assert!(realm.required);
    let token = prices.insertion_point("/Header/Credentials/token").unwrap();
    assert!(token.nillable);
    assert_eq!(token.kind, ValueKind::Binary);
    let values = BTreeMap::from([(
        String::from("/Header/Credentials/@realm"),
        String::from("a\"<b"),
    )]);
    assert!(
        prices
            .envelope_with(&values)
            .contains("realm=\"a&quot;&lt;b\"")
    );
}

#[test]
fn greath_wsdl20() {
    let spec = fixture("greath-2.0.wsdl");
    check_envelopes(&spec);
    assert_eq!(spec.version, WsdlVersion::Wsdl20);
    assert_eq!(
        spec.warnings,
        ["binding `reservationHTTPBinding` is not SOAP; skipped"]
    );
    let names: Vec<_> = spec
        .operations
        .iter()
        .map(|operation| operation.name.as_str())
        .collect();
    assert_eq!(names, ["opCheckAvailability", "opMakeReservation"]);

    let check = operation(&spec, "opCheckAvailability", SoapVersion::Soap12);
    assert_eq!(check.service.as_deref(), Some("reservationService"));
    assert_eq!(check.port.as_deref(), Some("reservationEndpoint"));
    assert_eq!(check.interface.as_deref(), Some("reservationInterface"));
    assert_eq!(
        check.documentation.as_deref(),
        Some("Checks room availability.")
    );
    assert_eq!(check.faults, ["invalidDataFault"]);
    assert_eq!(
        check.soap_action.as_deref(),
        Some("http://greath.example.com/2004/opCheckAvailability")
    );
    assert_eq!(
        check.request.url,
        "http://greath.example.com/2004/reservation"
    );
    assert_eq!(
        check.output[0].element.as_deref(),
        Some("{http://greath.example.com/2004/schemas/resSvc}checkAvailabilityResponse")
    );
    let elements = read_envelope(&check.envelope);
    assert_eq!(
        text_at(&elements, "/Envelope/Body/checkAvailability/checkInDate"),
        "2024-01-01"
    );
    let points: Vec<_> = check
        .insertion_points
        .iter()
        .map(|point| point.name.as_str())
        .collect();
    assert_eq!(
        points,
        [
            "/Body/checkAvailability/checkInDate",
            "/Body/checkAvailability/checkOutDate",
            "/Body/checkAvailability/roomType",
        ]
    );

    // Inherited through `extends`; `#any` output has no parts.
    let reserve = operation(&spec, "opMakeReservation", SoapVersion::Soap12);
    assert_eq!(reserve.output, Vec::new());
    assert_eq!(reserve.soap_action, None);
    assert_eq!(
        reserve.request.header("Content-Type"),
        Some("application/soap+xml; charset=utf-8")
    );
    assert_eq!(
        reserve
            .insertion_point("/Body/makeReservation/nights")
            .unwrap()
            .value,
        "1"
    );
}

#[test]
fn limits_and_options() {
    let path = format!(
        "{}/tests/fixtures/calculator.wsdl",
        env!("CARGO_MANIFEST_DIR")
    );
    let bytes = std::fs::read(path).unwrap();
    let spec = parse(&bytes, &Options::default().with_max_operations(3)).unwrap();
    assert!(spec.truncated);
    assert_eq!(spec.operations.len(), 3);

    let spec = parse(&bytes, &Options::default().with_max_nodes(2)).unwrap();
    let add = spec.operation("Add").unwrap();
    assert_eq!(add.body[0].children.len(), 1);
    assert!(
        spec.warnings
            .iter()
            .any(|warning| warning == "Add: sample message cut off at 2 nodes"),
        "{:?}",
        spec.warnings
    );
    check_envelopes(&spec);

    let error = parse(&bytes, &Options::default().with_max_input_bytes(100)).unwrap_err();
    assert_eq!(error.code(), "too_large");
}

#[test]
fn bindings_without_services_and_bad_references() {
    let wsdl = br#"<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
        xmlns:soap12="http://schemas.xmlsoap.org/wsdl/soap12/" xmlns:tns="urn:t"
        xmlns:xs="http://www.w3.org/2001/XMLSchema" targetNamespace="urn:t">
      <import namespace="urn:other" location="other.wsdl"/>
      <message name="In"><part name="p" element="tns:Missing"/><part name="q" type="tns:Nope"/></message>
      <portType name="PT"><operation name="Op"><input message="tns:In"/></operation></portType>
      <binding name="B" type="tns:PT">
        <soap12:binding style="document"/>
        <operation name="Op"><input><soap12:body use="literal"/></input></operation>
        <operation name="Ghost"/>
      </binding>
    </definitions>"#;
    let spec = parse(wsdl, &Options::default()).unwrap();
    check_envelopes(&spec);
    assert_eq!(spec.services, Vec::<String>::new());
    let names: Vec<_> = spec.operations.iter().map(|op| op.name.as_str()).collect();
    assert_eq!(names, ["Op", "Ghost"]);
    let op = &spec.operations[0];
    assert_eq!((op.service.as_deref(), op.address.as_deref()), (None, None));
    assert_eq!(op.request.url, rune_wsdl::DEFAULT_ENDPOINT);
    assert_eq!(
        spec.warnings,
        [
            "WSDL `other.wsdl` is not fetched; what it declares is missing",
            &format!("Op: element `{{{}}}Missing` is not declared", "urn:t"),
            &format!("Op: type `{{{}}}Nope` is not declared", "urn:t"),
            "operation `Ghost` of binding `B` is not in its port type",
        ]
    );
    // Unresolved parts still yield placeholder elements to mutate.
    let missing = op.insertion_point("/Body/Missing").unwrap();
    assert_eq!(missing.kind, ValueKind::Any);
    assert!(op.insertion_point("/Body/q").is_some());
}

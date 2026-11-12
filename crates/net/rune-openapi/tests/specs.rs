//! Imports of example specifications: a Petstore in `OpenAPI` 3.0 (YAML),
//! a 3.1 document and a Swagger 2.0 store.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test helpers")]

use rune_openapi::{
    ApiSpec, Endpoint, InsertionLocation, InsertionPoint, OpenApiError, Options, ParameterLocation,
    ParameterStyle, SchemaType, SecurityScheme, SpecVersion, Value, parse,
};
use serde_json::json;

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|error| panic!("{path}: {error}"))
}

fn by_op<'a>(spec: &'a ApiSpec, id: &str) -> &'a Endpoint {
    spec.endpoint(id)
        .unwrap_or_else(|| panic!("no operation {id}"))
}

fn point<'a>(
    endpoint: &'a Endpoint,
    location: InsertionLocation,
    name: &str,
) -> &'a InsertionPoint {
    endpoint.insertion_point(location, name).unwrap_or_else(|| {
        panic!(
            "no {location:?} point {name} in {:?}",
            endpoint.insertion_points
        )
    })
}

fn body_json(endpoint: &Endpoint) -> Value {
    serde_json::from_slice(endpoint.request.body.as_bytes()).unwrap()
}

#[cfg(feature = "yaml")]
mod petstore_30 {
    use rune_openapi::{ExampleStrategy, Url};

    use super::*;

    fn spec() -> ApiSpec {
        parse(&fixture("petstore-3.0.yaml"), &Options::default()).unwrap()
    }

    #[test]
    fn document_level() {
        let spec = spec();
        assert_eq!(spec.version, SpecVersion::OpenApi30);
        assert_eq!(spec.version_text, "3.0.3");
        assert_eq!(spec.title.as_deref(), Some("Petstore (fixture)"));
        assert_eq!(spec.api_version.as_deref(), Some("1.0.0"));
        assert_eq!(spec.servers, vec!["https://petstore.example.test/v1"]);
        assert_eq!(spec.endpoints.len(), 7);
        assert!(!spec.truncated);
        assert!(
            spec.warnings
                .iter()
                .any(|warning| warning.contains("common.yaml")),
            "external ref warning: {:?}",
            spec.warnings
        );
    }

    #[test]
    fn list_pets_query_parameters() {
        let spec = spec();
        let list = by_op(&spec, "listPets");
        assert_eq!(list.method, "GET");
        assert_eq!(list.path, "/pets");
        assert_eq!(list.pointer, "#/paths/~1pets/get");
        assert_eq!(list.summary.as_deref(), Some("List all pets"));
        assert_eq!(list.tags, vec!["pets"]);
        assert_eq!(
            list.request.url,
            "https://petstore.example.test/v1/pets?limit=1&status=available"
        );
        assert_eq!(
            list.request.header("Authorization"),
            Some("Bearer {{bearerAuth}}")
        );

        let limit = list.parameter("limit", ParameterLocation::Query).unwrap();
        assert_eq!(limit.schema.kind, SchemaType::Integer);
        assert_eq!(limit.schema.format.as_deref(), Some("int32"));
        assert_eq!(limit.schema.minimum, Some(1.0));
        assert_eq!(limit.schema.maximum, Some(100.0));
        assert_eq!(limit.style, ParameterStyle::Form);
        assert!(limit.explode);
        assert!(!limit.required);
        let status = point(list, InsertionLocation::Query, "status");
        assert_eq!(
            status.schema.enum_values,
            vec![json!("available"), json!("pending"), json!("sold")]
        );

        let ok = &list.responses[0];
        assert_eq!(ok.status, "200");
        let schema = &ok.content[0].schema;
        assert_eq!(schema.kind, SchemaType::Array);
        let pet = schema.items.as_deref().unwrap();
        assert_eq!(pet.name.as_deref(), Some("Pet"));
        let id = pet.property("id").unwrap();
        assert!(id.required, "allOf part marks id required");
        assert!(id.schema.read_only);
        assert!(
            pet.property("name").unwrap().required,
            "inherited from NewPet"
        );
    }

    #[test]
    fn create_pet_json_body() {
        let spec = spec();
        let create = by_op(&spec, "createPet");
        assert_eq!(create.request.method, "POST");
        assert_eq!(create.request.content_type(), Some("application/json"));
        let body_schema = &create.request_body.as_ref().unwrap();
        assert!(body_schema.required);
        assert_eq!(
            body_schema.content[0].schema.name.as_deref(),
            Some("NewPet")
        );

        let body = body_json(create);
        assert_eq!(body["name"], "doggie");
        assert_eq!(body["birthDate"], "2024-01-01T00:00:00Z");
        assert_eq!(body["owner"]["email"], "user@example.test");
        assert!(body.get("id").is_none());
        // NewPet.owner -> Owner.pets -> Pet -> allOf NewPet recurses: the
        // cycle is cut, and Pet keeps only its read-only id.
        assert_eq!(body["owner"]["pets"], json!([{}]));

        let name = point(create, InsertionLocation::JsonPointer, "/name");
        assert!(name.required);
        assert_eq!(name.value, "doggie");
        assert_eq!(name.schema_type(), SchemaType::String);
        assert_eq!(
            point(create, InsertionLocation::JsonPointer, "/birthDate")
                .schema
                .format
                .as_deref(),
            Some("date-time")
        );
        assert_eq!(
            point(create, InsertionLocation::JsonPointer, "/owner/email")
                .schema
                .format
                .as_deref(),
            Some("email")
        );
        assert!(!point(create, InsertionLocation::JsonPointer, "/tag").required);
    }

    #[test]
    fn path_item_parameters_and_security_overrides() {
        let spec = spec();
        let show = by_op(&spec, "showPetById");
        assert_eq!(
            show.request.url,
            "https://petstore.example.test/v1/pets/fido-7"
        );
        assert_eq!(show.request.header("X-API-Key"), Some("{{api_key}}"));
        assert_eq!(show.request.header("Authorization"), None);
        assert!(matches!(
            show.security[0].schemes[0].scheme,
            Some(SecurityScheme::ApiKey { .. })
        ));
        let pet_id = show.parameter("petId", ParameterLocation::Path).unwrap();
        assert!(pet_id.required);
        assert_eq!(pet_id.description.as_deref(), Some("The id of the pet"));
        assert_eq!(
            point(show, InsertionLocation::Path, "petId").value,
            "fido-7"
        );

        let delete = by_op(&spec, "deletePet");
        assert_eq!(delete.security.len(), 0, "security: [] disables auth");
        assert_eq!(delete.request.header("Authorization"), None);
        assert_eq!(
            delete.request.header("X-Request-ID"),
            Some("00000000-0000-4000-8000-000000000000")
        );
        assert!(point(delete, InsertionLocation::Header, "X-Request-ID").required);
    }

    #[test]
    fn form_and_multipart_bodies() {
        let spec = spec();
        let update = by_op(&spec, "updatePet");
        assert_eq!(update.request.method, "PUT");
        assert_eq!(update.request.body.as_utf8(), Some("age=0&name=rex"));
        assert_eq!(
            update.request.content_type(),
            Some("application/x-www-form-urlencoded")
        );
        let name = point(update, InsertionLocation::Form, "name");
        assert!(name.required);
        assert_eq!(
            point(update, InsertionLocation::Form, "age").schema_type(),
            SchemaType::Integer
        );

        let upload = by_op(&spec, "uploadPhoto");
        let content_type = upload.request.content_type().unwrap();
        assert_eq!(
            content_type,
            format!(
                "multipart/form-data; boundary={}",
                rune_openapi::MULTIPART_BOUNDARY
            )
        );
        let text = upload.request.body.as_utf8().unwrap();
        assert!(
            text.contains("name=\"caption\"\r\n\r\nstr\r\n"),
            "maxLength: {text}"
        );
        assert!(text.contains("name=\"file\"; filename=\"file.bin\""));
        assert!(
            point(upload, InsertionLocation::Multipart, "file")
                .schema
                .is_binary()
        );
    }

    #[test]
    fn options_override_server_auth_and_examples() {
        let options = Options::default()
            .with_base_url(Url::parse("http://127.0.0.1:8080/").unwrap())
            .with_base_path("/api")
            .with_auth_value("bearerAuth", "fake-token")
            .with_example_strategy(ExampleStrategy::TypeDefaults)
            .with_max_endpoints(2);
        let spec = parse(&fixture("petstore-3.0.yaml"), &options).unwrap();
        assert_eq!(spec.endpoints.len(), 2);
        assert!(spec.truncated);
        let list = by_op(&spec, "listPets");
        assert!(
            list.request
                .url
                .starts_with("http://127.0.0.1:8080/api/pets?")
        );
        assert_eq!(
            list.request.header("Authorization"),
            Some("Bearer fake-token")
        );
        let create = by_op(&spec, "createPet");
        assert_eq!(body_json(create)["name"], "string", "examples ignored");

        let rerendered = create.render(&Options::default());
        assert_eq!(
            rerendered.request.url,
            "https://petstore.example.test/v1/pets"
        );
        assert_eq!(rerendered.warnings, Vec::<String>::new());
    }
}

#[test]
fn openapi_31_json() {
    let spec = parse(&fixture("openapi-3.1.json"), &Options::default()).unwrap();
    assert_eq!(spec.version, SpecVersion::OpenApi31);
    assert_eq!(spec.endpoints.len(), 2);
    assert_eq!(spec.servers, vec!["https://eu.api.example.test/v2"]);

    let get = by_op(&spec, "getUser");
    assert_eq!(
        get.request.url,
        "https://eu.api.example.test/v2/users/1?filter%5Brole%5D=admin"
    );
    assert_eq!(get.request.header("Cookie"), Some("session=cookie-value-1"));
    let user_id = get.parameter("userId", ParameterLocation::Path).unwrap();
    assert_eq!(user_id.schema.kind, SchemaType::Integer);
    assert_eq!(user_id.schema.minimum, Some(0.0));
    assert!(user_id.schema.exclusive_minimum);
    let filter = get.parameter("filter", ParameterLocation::Query).unwrap();
    assert_eq!(filter.style, ParameterStyle::DeepObject);
    assert_eq!(
        point(get, InsertionLocation::Cookie, "session").value,
        "cookie-value-1"
    );

    let create = by_op(&spec, "createUser");
    assert_eq!(
        create.request.header("Authorization"),
        Some("Bearer {{oauth}}")
    );
    assert_eq!(create.security[0].schemes[0].scopes, vec!["users:write"]);
    assert_eq!(
        create.security[0].schemes[0].scheme,
        Some(SecurityScheme::OAuth2)
    );
    let body = body_json(create);
    assert_eq!(body["age"], 18, "minimum honoured");
    assert_eq!(body["score"], 3.5, "exclusiveMinimum honoured");
    assert_eq!(body["nickname"], "nick-1", "3.1 examples array");
    assert_eq!(body["kind"], "person", "oneOf picks first");
    let nickname = point(create, InsertionLocation::JsonPointer, "/nickname");
    assert_eq!(nickname.schema_type(), SchemaType::String);
    assert!(nickname.schema.nullable);
    assert!(point(create, InsertionLocation::JsonPointer, "/email").required);
    let kind = &create.request_body.as_ref().unwrap().content[0]
        .schema
        .property("kind")
        .unwrap()
        .schema;
    assert_eq!(kind.variants.len(), 2);
    let content_types: Vec<_> = create
        .request_body
        .as_ref()
        .unwrap()
        .content
        .iter()
        .map(|media| media.content_type.as_str())
        .collect();
    assert_eq!(content_types, vec!["application/json", "application/xml"]);
}

#[test]
fn swagger_20_json() {
    let spec = parse(&fixture("swagger-2.0.json"), &Options::default()).unwrap();
    assert_eq!(spec.version, SpecVersion::Swagger2);
    assert_eq!(
        spec.servers,
        vec![
            "https://store.example.test/v2",
            "http://store.example.test/v2"
        ]
    );
    assert_eq!(spec.endpoints.len(), 4);

    let order = by_op(&spec, "placeOrder");
    assert_eq!(
        order.request.url,
        "https://store.example.test/v2/store/order?api_key=%7B%7Bapi_key%7D%7D"
    );
    let body = body_json(order);
    assert_eq!(body["quantity"], 2, "default used");
    assert_eq!(body["status"], "placed");
    assert_eq!(
        point(order, InsertionLocation::JsonPointer, "/quantity")
            .schema
            .format
            .as_deref(),
        Some("int32")
    );
    let request_body = order.request_body.as_ref().unwrap();
    assert!(request_body.required);
    assert_eq!(request_body.content[0].content_type, "application/json");
    assert_eq!(
        request_body.content[0].schema.name.as_deref(),
        Some("Order")
    );

    let get = by_op(&spec, "getOrderById");
    assert_eq!(
        get.request.url,
        "https://store.example.test/v2/store/order/1"
    );
    let order_id = get.parameter("orderId", ParameterLocation::Path).unwrap();
    assert_eq!(order_id.schema.maximum, Some(10.0));

    let login = by_op(&spec, "loginUser");
    assert_eq!(
        login.request.url,
        "https://store.example.test/v2/user/login?username=alice&tags=a"
    );
    assert_eq!(
        login.request.header("Authorization"),
        Some("Basic {{basic}}")
    );
    let tags = login.parameter("tags", ParameterLocation::Query).unwrap();
    assert_eq!(tags.schema.kind, SchemaType::Array);
    assert!(tags.explode, "collectionFormat multi");
    assert_eq!(
        tags.schema.items.as_ref().unwrap().enum_values,
        vec![json!("a"), json!("b")]
    );

    let upload = by_op(&spec, "uploadFile");
    let media = &upload.request_body.as_ref().unwrap().content[0];
    assert_eq!(media.content_type, "multipart/form-data");
    assert!(media.schema.property("file").unwrap().schema.is_binary());
    assert!(
        upload
            .request
            .content_type()
            .unwrap()
            .starts_with("multipart/form-data; boundary=")
    );
    let text = upload.request.body.as_utf8().unwrap();
    assert!(text.contains("meta"));
    assert!(text.contains("filename=\"file.bin\""));
    assert_eq!(
        point(upload, InsertionLocation::Multipart, "additionalMetadata").value,
        "meta"
    );
}

#[test]
fn swagger_20_form_and_responses() {
    let doc = json!({
        "swagger": "2.0",
        "host": "api.example.test",
        "produces": ["application/json", "application/xml"],
        "paths": {"/login": {"post": {
            "parameters": [
                {"name": "user", "in": "formData", "type": "string", "required": true},
                {"name": "ids", "in": "query", "type": "array", "items": {"type": "integer"},
                 "collectionFormat": "pipes"}
            ],
            "responses": {
                "200": {"description": "ok", "schema": {"type": "object",
                    "properties": {"token": {"type": "string"}}},
                    "examples": {"application/json": {"token": "t"}}},
                "default": {"description": "error"}
            }
        }}}
    });
    let spec = rune_openapi::from_value(&doc, &Options::default()).unwrap();
    let login = &spec.endpoints[0];
    assert_eq!(login.request.url, "https://api.example.test/login?ids=1");
    assert_eq!(login.request.body.as_utf8(), Some("user=string"));
    assert_eq!(
        login.request.content_type(),
        Some("application/x-www-form-urlencoded")
    );
    assert_eq!(
        login
            .parameter("ids", ParameterLocation::Query)
            .unwrap()
            .style,
        ParameterStyle::PipeDelimited
    );
    assert_eq!(login.responses.len(), 2);
    let ok = &login.responses[0];
    assert_eq!(ok.content.len(), 2);
    assert_eq!(ok.content[0].example, Some(json!({"token": "t"})));
    assert_eq!(login.responses[1].status, "default");
    assert_eq!(login.responses[1].content.len(), 0);
}

#[test]
fn rejects_other_documents() {
    let error = parse(
        b"{\"openapi\": \"4.0.0\", \"paths\": {}}",
        &Options::default(),
    )
    .unwrap_err();
    assert_eq!(error, OpenApiError::UnsupportedVersion("4.0.0".into()));
    let error = parse(b"{\"info\": {}}", &Options::default()).unwrap_err();
    assert_eq!(error.code(), "not_openapi");
    let error = parse(b"{", &Options::default()).unwrap_err();
    assert_eq!(error.code(), "parse_error");
}

#[cfg(feature = "serde")]
#[test]
fn model_round_trips_through_json() {
    let spec = parse(&fixture("openapi-3.1.json"), &Options::default()).unwrap();
    let encoded = serde_json::to_string(&spec).unwrap();
    let decoded: ApiSpec = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded, spec);
}

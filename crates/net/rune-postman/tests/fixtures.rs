//! Imports of collections, environments and globals as the Postman app
//! exports them (`tests/fixtures/`), plus the quirks seen in the wild.

#![allow(clippy::unwrap_used, reason = "test helpers")]

use rune_postman::{
    Collection, CollectionRequest, MULTIPART_BOUNDARY, ReadOptions, parse_environment, read,
};

const SHOP: &[u8] = include_bytes!("fixtures/shop.postman_collection.json");
const STAGING: &[u8] = include_bytes!("fixtures/staging.postman_environment.json");
const GLOBALS: &[u8] = include_bytes!("fixtures/workspace.postman_globals.json");
const LEGACY: &[u8] = include_bytes!("fixtures/legacy-v2.0.postman_collection.json");

fn shop_on_staging() -> Collection {
    let options = ReadOptions::default()
        .with_environment(parse_environment(STAGING).unwrap())
        .with_globals(parse_environment(GLOBALS).unwrap());
    read(SHOP, &options).unwrap()
}

fn find<'a>(collection: &'a Collection, path: &str) -> &'a CollectionRequest {
    collection
        .requests
        .iter()
        .find(|request| request.path() == path)
        .unwrap()
}

fn warning_codes(collection: &Collection) -> Vec<(String, &'static str)> {
    collection
        .warnings
        .iter()
        .map(|warning| (warning.path.clone().unwrap_or_default(), warning.code))
        .collect()
}

#[test]
fn shop_metadata_and_order() {
    let shop = shop_on_staging();
    assert_eq!(shop.name, "Shop API");
    assert_eq!(
        shop.id.as_deref(),
        Some("6f1c1a52-8a1e-4c55-9c2e-0a4c2b7d9e10")
    );
    assert!(shop.schema.as_deref().unwrap().contains("v2.1.0"));
    assert_eq!(shop.variables.len(), 4);
    let paths: Vec<String> = shop.requests.iter().map(CollectionRequest::path).collect();
    assert_eq!(
        paths,
        [
            "Auth/Login",
            "Catalog/Products/List products",
            "Catalog/Products/Get product",
            "Catalog/Products/Create product",
            "Catalog/Upload image",
            "Partners/Partner feed",
            "Partners/Partner OAuth",
            "Partners/Legacy digest",
            "Search (GraphQL)",
            "Health",
        ]
    );
    assert_eq!(
        warning_codes(&shop),
        [
            ("Catalog".to_owned(), "script_value_not_literal"),
            (
                "Catalog/Products/Create product".to_owned(),
                "unresolved_variable"
            ),
            ("Catalog/Upload image".to_owned(), "file_not_embedded"),
            ("Partners/Legacy digest".to_owned(), "auth_not_applied"),
        ]
    );
}

#[test]
fn environment_wins_over_collection_and_globals() {
    let shop = shop_on_staging();
    let login = find(&shop, "Auth/Login");
    assert_eq!(login.request.method, "POST");
    assert_eq!(
        login.request.url,
        "https://staging.shop.example.test/auth/login"
    );
    assert_eq!(
        login.request.body.as_utf8(),
        Some("username=qa%40example.test&password=not-a-real-password")
    );
    assert_eq!(
        login.request.content_type(),
        Some("application/x-www-form-urlencoded")
    );
    assert_eq!(login.request.header("Authorization"), None, "noauth");
    assert_eq!(
        login.description.as_deref(),
        Some("Exchanges credentials for a session token.")
    );
    // Only pre-request scripts are kept; the login's test script is not.
    assert_eq!(login.pre_request_scripts.len(), 1);
}

#[test]
fn folder_scripts_and_inherited_bearer_auth() {
    let shop = shop_on_staging();
    let list = find(&shop, "Catalog/Products/List products");
    // `apiVersion` comes from the Catalog script; `pageSize` is disabled in
    // the environment, so the collection value applies.
    assert_eq!(
        list.request.url,
        "https://staging.shop.example.test/v2/products?page=1&limit=20"
    );
    assert_eq!(list.request.headers.len(), 2, "{:?}", list.request.headers);
    assert_eq!(list.request.header("Accept"), Some("application/json"));
    assert_eq!(
        list.request.header("Authorization"),
        Some("Bearer staging-token")
    );
    assert_eq!(list.folders, ["Catalog", "Products"]);
    assert_eq!(list.pre_request_scripts.len(), 2);
    assert!(list.pre_request_scripts[1].contains("pm.collectionVariables.set"));
    assert_eq!(list.unresolved.len(), 0);

    let get = find(&shop, "Catalog/Products/Get product");
    assert_eq!(
        get.request.url,
        "https://staging.shop.example.test/v2/products/1001"
    );
}

#[test]
fn raw_json_body_with_item_script_value() {
    let shop = shop_on_staging();
    let create = find(&shop, "Catalog/Products/Create product");
    assert_eq!(
        create.request.body.as_utf8(),
        Some("{\n    \"sku\": \"SKU-0042\",\n    \"name\": \"Mug\",\n    \"price\": 12.5\n}")
    );
    assert_eq!(create.request.content_type(), Some("application/json"));
    // `requestId` is computed by a script, so it stays a placeholder.
    assert_eq!(create.request.header("X-Request-Id"), Some("{{requestId}}"));
    assert_eq!(create.unresolved, ["requestId"]);
    assert_eq!(create.pre_request_scripts.len(), 3);
}

#[test]
fn multipart_body_with_file_part() {
    let shop = shop_on_staging();
    let upload = find(&shop, "Catalog/Upload image");
    assert_eq!(
        upload.request.url,
        "https://staging.shop.example.test/v2/products/1001/image"
    );
    assert_eq!(
        upload.request.content_type(),
        Some(format!("multipart/form-data; boundary={MULTIPART_BOUNDARY}").as_str())
    );
    let b = MULTIPART_BOUNDARY;
    let expected = format!(
        "--{b}\r\nContent-Disposition: form-data; name=\"alt\"\r\n\r\nA blue mug\r\n\
         --{b}\r\nContent-Disposition: form-data; name=\"image\"; filename=\"mug.png\"\r\n\
         Content-Type: application/octet-stream\r\n\r\n\r\n--{b}--\r\n",
    );
    assert_eq!(upload.request.body.as_utf8(), Some(expected.as_str()));
}

#[test]
fn folder_api_key_oauth2_and_unsupported_auth() {
    let shop = shop_on_staging();
    let feed = find(&shop, "Partners/Partner feed");
    assert_eq!(
        feed.request.url,
        "https://staging.shop.example.test/partners/feed?format=xml&api_key=global-partner-key"
    );
    assert_eq!(feed.request.header("Authorization"), None);

    let oauth = find(&shop, "Partners/Partner OAuth");
    assert_eq!(
        oauth.request.header("Authorization"),
        Some("Bearer partner-access-token")
    );

    let digest = find(&shop, "Partners/Legacy digest");
    assert_eq!(digest.request.header("Authorization"), None);
}

#[test]
fn graphql_body() {
    let shop = shop_on_staging();
    let search = find(&shop, "Search (GraphQL)");
    let body: serde_json::Value = serde_json::from_slice(search.request.body.as_bytes()).unwrap();
    assert_eq!(
        body["variables"],
        serde_json::json!({"q": "mug", "first": 20})
    );
    assert!(body["query"].as_str().unwrap().starts_with("query Search"));
    assert_eq!(search.request.content_type(), Some("application/json"));
    assert_eq!(
        search.request.header("Authorization"),
        Some("Bearer staging-token")
    );

    let health = find(&shop, "Health");
    assert_eq!(health.request.method, "HEAD");
    assert_eq!(health.request.headers.len(), 0);
}

#[test]
fn without_environment_the_collection_values_apply() {
    let shop = read(SHOP, &ReadOptions::default()).unwrap();
    let login = find(&shop, "Auth/Login");
    assert_eq!(login.request.url, "https://shop.example.test/auth/login");
    assert_eq!(login.unresolved, ["username", "password"]);
    let list = find(&shop, "Catalog/Products/List products");
    assert_eq!(
        list.request.header("Authorization"),
        Some("Bearer {{token}}")
    );
    assert_eq!(list.unresolved, ["token"]);
}

#[test]
fn overrides_auth_and_scripts_can_be_switched() {
    let options = ReadOptions::default()
        .with_environment(parse_environment(STAGING).unwrap())
        .with_variable("baseUrl", "http://127.0.0.1:8080")
        .with_variable("requestId", "req-1")
        .with_auth(false)
        .with_script_values(false);
    let shop = read(SHOP, &options).unwrap();
    let create = find(&shop, "Catalog/Products/Create product");
    assert_eq!(create.request.url, "http://127.0.0.1:8080/v1/products");
    assert_eq!(create.request.header("X-Request-Id"), Some("req-1"));
    assert_eq!(create.request.header("Authorization"), None);
    assert_eq!(create.unresolved, ["sku"]);
    assert_eq!(create.pre_request_scripts.len(), 3, "kept as data");
}

#[test]
fn legacy_v2_0_collection() {
    let options = ReadOptions::default()
        .with_variable("adminPassword", "s3cret")
        .with_variable("email", "a@b.test");
    let legacy = read(LEGACY, &options).unwrap();
    assert!(legacy.warnings.is_empty(), "{:?}", legacy.warnings);
    assert_eq!(
        legacy.description.as_deref(),
        Some("Exported as Collection v2.0.")
    );
    assert_eq!(legacy.variables[1].key, "port");
    assert_eq!(legacy.variables[1].value, "8080");

    let find_account = find(&legacy, "Accounts/Find account");
    assert_eq!(
        find_account.request.url,
        "http://legacy.example.test:8080/accounts/search?email=a@b.test"
    );
    assert_eq!(
        find_account.request.header("Accept"),
        Some("application/xml")
    );
    assert_eq!(find_account.request.header("X-Trace"), Some("on"));
    assert_eq!(
        find_account.request.header("Authorization"),
        Some("Basic YWRtaW46czNjcmV0")
    );

    let ping = find(&legacy, "Accounts/Ping");
    assert_eq!(ping.request.method, "GET");
    assert_eq!(ping.request.url, "http://legacy.example.test:8080/ping");

    let rotate = find(&legacy, "Accounts/Rotate key");
    assert_eq!(rotate.request.method, "PUT");
    assert_eq!(
        rotate.request.url,
        "http://legacy.example.test:8080/accounts/:accountId/key"
    );
    let authorization: Vec<&str> = rotate.request.header_values("Authorization").collect();
    assert_eq!(
        authorization,
        ["Bearer manual-override"],
        "explicit header wins"
    );
    assert_eq!(
        rotate.request.body.as_utf8(),
        Some("<rotate reason=\"scheduled\"/>")
    );
    assert_eq!(rotate.request.content_type(), None);
}

#[test]
fn environment_fixtures() {
    let staging = parse_environment(STAGING).unwrap();
    assert_eq!(staging.name, "Staging");
    assert_eq!(staging.scope.as_deref(), Some("environment"));
    assert_eq!(staging.values.len(), 6);
    assert!(staging.values[2].secret);
    assert_eq!(staging.get("pageSize"), None);
    let globals = parse_environment(GLOBALS).unwrap();
    assert_eq!(globals.scope.as_deref(), Some("globals"));
    assert_eq!(globals.get("partnerKey"), Some("global-partner-key"));
}

#[test]
fn malformed_items_are_skipped_with_warnings() {
    let input = br#"{"info": {"name": "Quirks"}, "item": [
        7,
        {"name": "bad request", "request": 5},
        {"name": "bad header", "request": {"url": "h.test", "header": 5}},
        {"name": "bad body", "request": {"url": "h.test", "body": []}},
        {"name": "no url", "request": {"method": "GET"}},
        {"name": "empty"},
        {"name": "bad folder", "item": {"x": 1}},
        {"name": "ok", "request": {"url": "h.test/ok", "header": [null, {"key": "", "value": "x"}, {"key": "A", "value": 1}]}}
    ]}"#;
    let collection = read(input, &ReadOptions::default()).unwrap();
    assert_eq!(collection.requests.len(), 1);
    let ok = &collection.requests[0];
    assert_eq!(ok.request.url, "http://h.test/ok");
    assert_eq!(ok.request.header("A"), Some("1"));
    assert_eq!(ok.request.headers.len(), 1);
    let codes: Vec<&str> = collection.warnings.iter().map(|w| w.code).collect();
    assert_eq!(
        codes,
        [
            "invalid_item",
            "invalid_item",
            "invalid_item",
            "invalid_item",
            "invalid_item",
            "no_request",
            "invalid_item"
        ]
    );
    assert_eq!(
        collection.warnings[0].to_string(),
        "#0: skipped: not an object"
    );
}

#[test]
fn wrappers_bom_and_errors() {
    let wrapped = b"\xef\xbb\xbf{\"collection\": {\"info\": {\"name\": \"W\"}, \"item\": [{\"name\": \"a\", \"request\": \"https://h.test/\"}]}}";
    let collection = read(wrapped, &ReadOptions::default()).unwrap();
    assert_eq!(collection.name, "W");
    assert_eq!(collection.requests[0].request.url, "https://h.test/");

    let v1 = br#"{"id": "x", "name": "old", "requests": [], "folders": []}"#;
    let error = read(v1, &ReadOptions::default()).unwrap_err();
    assert_eq!(error.code(), "not_collection");
    assert!(error.to_string().contains("v1"));
    assert_eq!(
        read(b"{\"item\": 3}", &ReadOptions::default())
            .unwrap_err()
            .code(),
        "not_collection"
    );
    assert_eq!(
        read(b"nope", &ReadOptions::default()).unwrap_err().code(),
        "invalid_json"
    );
}

#[test]
fn limits() {
    let input = br#"{"item": [
        {"name": "a", "request": "h.test/a"},
        {"name": "b", "request": "h.test/b"},
        {"name": "c", "request": "h.test/c"}
    ]}"#;
    let collection = read(input, &ReadOptions::default().with_max_requests(2)).unwrap();
    assert_eq!(collection.requests.len(), 2);
    assert_eq!(collection.warnings[0].code, "max_requests");

    // Every level doubles the value: expansion stops at the limit.
    let mut variables = vec![r#"{"key": "v0", "value": "xxxxxxxxxxxxxxxx"}"#.to_owned()];
    for level in 1..13 {
        let previous = format!("{{{{v{}}}}}", level - 1);
        variables.push(format!(
            r#"{{"key": "v{level}", "value": "{previous}{previous}"}}"#
        ));
    }
    let bomb = format!(
        r#"{{"variable": [{}], "item": [{{"name": "bomb", "request": "h.test/{{{{v12}}}}"}}]}}"#,
        variables.join(",")
    );
    let options = ReadOptions::default().with_max_resolved_len(4096);
    let collection = read(bomb.as_bytes(), &options).unwrap();
    assert_eq!(
        collection.requests[0].request.url.len(),
        4096 + "http://".len()
    );
    assert_eq!(collection.warnings[0].code, "expansion_limit");

    // Folders nested past the limit are skipped, not recursed into.
    let mut deep = r#"{"name": "leaf", "request": "h.test"}"#.to_owned();
    for _ in 0..60 {
        deep = format!(r#"{{"name": "f", "item": [{deep}]}}"#);
    }
    let deep = format!(r#"{{"item": [{deep}]}}"#);
    let collection = read(deep.as_bytes(), &ReadOptions::default()).unwrap();
    assert_eq!(collection.requests.len(), 1);
}

//! Fixture schemas: every generated operation validates against its schema
//! and respects the depth bound.

#![allow(clippy::unwrap_used, reason = "test helpers")]

use std::fmt::Write as _;

use rune_graphql::{
    ExampleStrategy, GraphQlSpec, OperationKind, Options, SchemaSource, Transport, TypeKind, Url,
    Value, parse, parse_introspection, parse_sdl, query_depth, validate,
};

const STARWARS: &[u8] = include_bytes!("fixtures/starwars.graphql");
const SHOP: &[u8] = include_bytes!("fixtures/shop.graphql");
const COUNTRIES: &[u8] = include_bytes!("fixtures/countries-introspection.json");

fn options() -> Options {
    Options::default().with_endpoint(Url::parse("https://api.example.test/graphql").unwrap())
}

/// Every operation is valid, within the bound, and measured correctly.
fn assert_sound(spec: &GraphQlSpec, max_depth: usize) {
    for operation in &spec.operations {
        let errors = validate(&operation.document, &spec.schema);
        assert!(errors.is_empty(), "{}: {errors:?}", operation.document);
        let depth = query_depth(&operation.document).unwrap();
        assert_eq!(depth, operation.depth, "{}", operation.document);
        assert!(
            depth <= max_depth.max(2),
            "{depth} > {max_depth}: {}",
            operation.document
        );
        let body: Value = serde_json::from_str(operation.request.body.as_utf8().unwrap()).unwrap();
        assert_eq!(body["query"], operation.document.as_str());
        assert_eq!(body["variables"], operation.variables);
        assert_eq!(body["operationName"], operation.name.as_str());
        for point in &operation.insertion_points {
            assert_eq!(
                operation.variables.pointer(&point.name),
                Some(&point.value),
                "{}",
                point.name
            );
            assert!(point.kind.is_leaf());
        }
    }
}

#[test]
fn fixtures_validate_at_every_depth() {
    for input in [STARWARS, SHOP, COUNTRIES] {
        for depth in 1..=7 {
            for strategy in [
                ExampleStrategy::PreferDefaults,
                ExampleStrategy::TypeDefaults,
            ] {
                let options = options()
                    .with_max_depth(depth)
                    .with_subscriptions(true)
                    .with_example_strategy(strategy);
                let spec = parse(input, &options).unwrap();
                assert_ne!(spec.operations.len(), 0);
                assert_sound(&spec, depth);
            }
        }
    }
}

#[test]
fn starwars() {
    let spec = parse(STARWARS, &options().with_max_depth(3)).unwrap();
    assert_eq!(spec.source, SchemaSource::Sdl);
    assert!(spec.warnings.is_empty(), "{:?}", spec.warnings);
    let coordinates: Vec<_> = spec
        .operations
        .iter()
        .map(|op| op.coordinate.as_str())
        .collect();
    assert_eq!(coordinates, ["Query.hero", "Query.human", "Query.droid"]);
    let hero = spec.operation("Query.hero").unwrap();
    assert_eq!(
        hero.document,
        "query Hero($episode: Episode) { hero(episode: $episode) { id name appearsIn secretBackstory } }"
    );
    // `friends: [Character]` re-enters `Character`, already on the path.
    assert_eq!(hero.variables, serde_json::json!({"episode": "NEW_HOPE"}));
    let episode = hero.insertion_point("/episode").unwrap();
    assert_eq!(episode.kind, TypeKind::Enum);
    assert_eq!(episode.enum_values, ["NEW_HOPE", "EMPIRE", "JEDI"]);
    assert!(!episode.required);
    let human = spec.operation("Query.human").unwrap();
    assert!(human.insertion_point("/id").unwrap().required);
    assert_eq!(human.depth, 3);
    let character = spec.schema.get("Character").unwrap();
    assert_eq!(
        character.description.as_deref(),
        Some("A character in the Star Wars Trilogy")
    );
    assert_eq!(spec.schema.possible_types("Character"), ["Droid", "Human"]);
    // `secretBackstory` is reachable from all three entry points.
    assert_eq!(
        spec.operations_for_field("Character.secretBackstory")
            .count(),
        3
    );
    assert_eq!(
        spec.operations_for_field("Human.secretBackstory").count(),
        1
    );
    assert_eq!(spec.operations_for_type("Character").count(), 3);
}

#[test]
fn shop() {
    let spec = parse(SHOP, &options().with_subscriptions(true)).unwrap();
    assert!(spec.warnings.is_empty(), "{:?}", spec.warnings);
    let schema = &spec.schema;
    assert_eq!(schema.subscription_type.as_deref(), Some("Subscription"));
    assert!(schema.get("UserLookup").unwrap().one_of);
    assert_eq!(schema.get("OrderStatus").unwrap().enum_values.len(), 5);
    assert_eq!(schema.get("Timestamped").unwrap().interfaces, ["Node"]);
    assert_eq!(schema.possible_types("Node").len(), 4);
    let user = schema.get("User").unwrap();
    assert_eq!(
        user.field("passwordHash")
            .unwrap()
            .deprecation_reason
            .as_deref(),
        Some("never exposed")
    );

    let kinds: Vec<_> = spec.operations.iter().map(|op| op.kind).collect();
    assert_eq!(
        kinds
            .iter()
            .filter(|kind| **kind == OperationKind::Query)
            .count(),
        9
    );
    assert_eq!(
        kinds
            .iter()
            .filter(|kind| **kind == OperationKind::Mutation)
            .count(),
        5
    );
    assert_eq!(kinds.last(), Some(&OperationKind::Subscription));

    let create = spec.operation("Mutation.createOrder").unwrap();
    assert_eq!(
        create.variables,
        serde_json::json!({"input": {
            "customer": {"id": "1"},
            "lines": [{"sku": "string", "quantity": 1}],
            "shipping": {"line1": "string", "city": "string", "country": "DE"},
            "note": "string"
        }})
    );
    let pointers: Vec<_> = create
        .insertion_points
        .iter()
        .map(|p| p.name.as_str())
        .collect();
    assert_eq!(
        pointers,
        [
            "/input/customer/id",
            "/input/lines/0/quantity",
            "/input/lines/0/sku",
            "/input/note",
            "/input/shipping/city",
            "/input/shipping/country",
            "/input/shipping/line1"
        ]
    );
    assert!(
        create
            .insertion_point("/input/lines/0/quantity")
            .unwrap()
            .required
    );

    // Nested required arguments become variables.
    let product = spec.operation("Query.product").unwrap();
    assert!(
        product.document.contains("$reviews_minRating: Int!"),
        "{}",
        product.document
    );
    assert!(
        product
            .document
            .contains("reviews(minRating: $reviews_minRating)")
    );

    // Unions select `__typename` plus one fragment per member.
    let search = spec.operation("Query.search").unwrap();
    assert!(
        search.document.contains("__typename ... on User {"),
        "{}",
        search.document
    );
    assert!(search.document.contains("... on Product {"));

    // Field-level authorization: every operation that can read a user email.
    let readers: Vec<_> = spec
        .operations_for_field("User.email")
        .map(|op| op.coordinate.as_str())
        .collect();
    assert!(readers.contains(&"Query.me"));
    assert!(readers.contains(&"Mutation.updateRole"));
    assert!(spec.operations_by_type()["Order"].len() >= 4);

    let no_deprecated = parse(SHOP, &options().with_deprecated(false)).unwrap();
    assert_eq!(
        no_deprecated
            .operations_for_field("User.passwordHash")
            .count(),
        0
    );
    assert!(spec.operations_for_field("User.passwordHash").count() > 0);
}

#[test]
fn countries_introspection() {
    let spec = parse(COUNTRIES, &options().with_max_depth(2)).unwrap();
    assert_eq!(spec.source, SchemaSource::Introspection);
    assert!(spec.warnings.is_empty(), "{:?}", spec.warnings);
    assert!(spec.schema.get("__Schema").is_none());
    assert_eq!(spec.operations.len(), 5);
    let countries = spec.operation("Query.countries").unwrap();
    assert_eq!(
        countries.document,
        "query Countries($filter: CountryFilterInput) { countries(filter: $filter) { capital code currency name } }"
    );
    assert_eq!(countries.variables, serde_json::json!({"filter": {}}));
    let typed = parse(
        COUNTRIES,
        &options().with_example_strategy(ExampleStrategy::TypeDefaults),
    )
    .unwrap();
    let filter = &typed.operation("Query.countries").unwrap().variables["filter"];
    assert_eq!(filter["code"]["in"], serde_json::json!(["string"]));
    let field = spec.schema.field("Country", "currency").unwrap();
    assert!(field.deprecated);
    assert_eq!(
        field.deprecation_reason.as_deref(),
        Some("Use `currencies`.")
    );
}

#[test]
fn sdl_and_introspection_agree() {
    for input in [STARWARS, SHOP] {
        let schema = parse_sdl(std::str::from_utf8(input).unwrap()).unwrap();
        let again = parse_introspection(&schema.to_introspection()).unwrap();
        assert_eq!(again.types, schema.types);
        let options = options().with_subscriptions(true);
        let left = rune_graphql::generate(schema, &options);
        let right = rune_graphql::generate(again, &options);
        let documents = |spec: &GraphQlSpec| -> Vec<String> {
            spec.operations
                .iter()
                .map(|op| op.document.clone())
                .collect()
        };
        assert_eq!(documents(&left), documents(&right));
    }
}

#[test]
fn bounds_hold_on_wide_schemas() {
    let mut sdl = String::from("type Query { root: T0 }\n");
    for index in 0..20 {
        let _ = write!(sdl, "type T{index} {{");
        for field in 0..50 {
            let _ = write!(sdl, " f{field}: T{}", (index + field) % 20);
        }
        sdl.push_str(" leaf: Int }\n");
    }
    let options = options()
        .with_max_depth(6)
        .with_max_fields_per_selection(8)
        .with_max_selections(100);
    let spec = parse(sdl.as_bytes(), &options).unwrap();
    let root = spec.operation("Query.root").unwrap();
    assert!(root.fields.len() <= 101);
    assert!(root.document.matches('{').count() <= 101);
    assert_sound(&spec, 6);
}

#[test]
fn get_transport_and_rerender() {
    let spec = parse(STARWARS, &options()).unwrap();
    let human = spec.operation("Query.human").unwrap();
    let get = human.to_request(&options().with_transport(Transport::Get));
    assert_eq!(get.method, "GET");
    let url = get.parsed_url().unwrap();
    let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
    assert_eq!(pairs[0], ("query".into(), human.document.clone()));
    assert_eq!(pairs[1], ("variables".into(), r#"{"id":"string"}"#.into()));
    let payload = human.to_request_with(&serde_json::json!({"id": "' OR 1=1--"}), &options());
    assert!(payload.body.as_utf8().unwrap().contains("' OR 1=1--"));
}

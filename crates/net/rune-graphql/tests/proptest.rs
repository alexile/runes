//! Property tests: parsing never panics; for random schemas every
//! generated operation validates and respects the depth bound; the
//! introspection codec round-trips.

use std::fmt::Write as _;

use proptest::prelude::*;
use rune_graphql::{
    Options, Value, generate, parse, parse_introspection, parse_sdl, query_depth, validate,
};

/// A field type: a named type index, wrapped in list / non-null.
#[derive(Debug, Clone)]
struct FieldSpec {
    target: usize,
    list: bool,
    non_null: bool,
    argument: Option<(usize, bool)>,
}

/// Renders a random schema: `Query` plus object types `T*`, an interface,
/// a union, an enum and input types, wired by the generated indices.
fn render(objects: &[Vec<FieldSpec>]) -> String {
    let count = objects.len();
    let scalars = [
        "Int", "String", "Boolean", "ID", "Float", "Color", "Filter", "Node", "Any", "Json",
    ];
    let output_name = |target: usize| -> String {
        if target < count {
            format!("T{target}")
        } else {
            match scalars[(target - count) % scalars.len()] {
                "Filter" => String::from("String"),
                other => other.to_owned(),
            }
        }
    };
    let input_names = ["Int", "String", "Color", "Filter", "ID", "Json", "Boolean"];
    let mut sdl = String::from(
        "enum Color { RED GREEN }\nscalar Json\n\
         input Filter { name: String, color: Color = RED, child: Filter, ids: [ID!]! }\n\
         interface Node { id: ID! }\n",
    );
    let _ = writeln!(
        sdl,
        "union Any = {}",
        (0..count)
            .map(|index| format!("T{index}"))
            .collect::<Vec<_>>()
            .join(" | ")
    );
    let render_field = |index: usize, field: &FieldSpec| {
        let mut ty = output_name(field.target);
        if field.list {
            ty = format!("[{ty}]");
        }
        if field.non_null {
            ty.push('!');
        }
        let argument = field
            .argument
            .map_or_else(String::new, |(input, required)| {
                format!(
                    "(arg: {}{})",
                    input_names[input % input_names.len()],
                    if required { "!" } else { "" }
                )
            });
        format!("  f{index}{argument}: {ty}\n")
    };
    for (index, fields) in objects.iter().enumerate() {
        let _ = write!(sdl, "type T{index} implements Node {{\n  id: ID!\n");
        for (field_index, field) in fields.iter().enumerate() {
            sdl.push_str(&render_field(field_index, field));
        }
        sdl.push_str("}\n");
    }
    sdl.push_str("type Query {\n");
    for (index, fields) in objects.iter().enumerate() {
        for (field_index, field) in fields.iter().enumerate().take(2) {
            sdl.push_str(&render_field(index * 10 + field_index, field));
        }
    }
    sdl.push_str("  any: [Any]\n  node(id: ID!): Node\n}\n");
    sdl.push_str("type Mutation {\n  save(input: Filter!, id: ID): T0\n}\n");
    sdl
}

fn schema_strategy() -> impl Strategy<Value = Vec<Vec<FieldSpec>>> {
    (1usize..6).prop_flat_map(|count| {
        let field = (
            0..count + 10,
            any::<bool>(),
            any::<bool>(),
            proptest::option::of((0usize..7, any::<bool>())),
        )
            .prop_map(|(target, list, non_null, argument)| FieldSpec {
                target,
                list,
                non_null,
                argument,
            });
        prop::collection::vec(prop::collection::vec(field, 0..6), count)
    })
}

proptest! {
    #[test]
    fn arbitrary_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let _ = parse(&bytes, &Options::default());
    }

    #[test]
    fn arbitrary_text_never_panics(text in "[{}()\\[\\]:!=@$&|.\"#a-zA-Z0-9 \n_-]{0,200}") {
        let schema = parse_sdl("type Query { a(x: Int): Int b: Query }").unwrap();
        let _ = parse(text.as_bytes(), &Options::default());
        let _ = validate(&text, &schema);
        let _ = query_depth(&text);
    }

    #[test]
    fn generated_operations_validate(objects in schema_strategy(), depth in 1usize..6, fields in 1usize..6) {
        let sdl = render(&objects);
        let schema = parse_sdl(&sdl).unwrap();
        prop_assert!(schema.warnings.is_empty(), "{:?}\n{sdl}", schema.warnings);
        let options = Options::default()
            .with_max_depth(depth)
            .with_max_fields_per_selection(fields)
            .with_max_selections(64);
        let spec = generate(schema, &options);
        prop_assert!(!spec.operations.is_empty());
        for operation in &spec.operations {
            let errors = validate(&operation.document, &spec.schema);
            prop_assert!(errors.is_empty(), "{}\n{errors:?}\n{sdl}", operation.document);
            let measured = query_depth(&operation.document).unwrap();
            prop_assert_eq!(measured, operation.depth);
            prop_assert!(measured <= depth.max(2), "{} > {depth}: {}", measured, operation.document);
            for point in &operation.insertion_points {
                prop_assert_eq!(operation.variables.pointer(&point.name), Some(&point.value));
            }
        }
    }

    #[test]
    fn introspection_round_trips(objects in schema_strategy()) {
        let schema = parse_sdl(&render(&objects)).unwrap();
        let json: Value = schema.to_introspection();
        let text = serde_json::to_string(&json).unwrap();
        let again = parse_introspection(&serde_json::from_str(&text).unwrap()).unwrap();
        prop_assert_eq!(&again.types, &schema.types);
        prop_assert_eq!(&again.query_type, &schema.query_type);
        prop_assert_eq!(&again.mutation_type, &schema.mutation_type);
    }
}

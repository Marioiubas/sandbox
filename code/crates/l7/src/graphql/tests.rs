use super::*;
use proptest::prelude::*;

#[test]
fn parses_operations_fragments_and_values() {
    let d = parse(
        r#"
        # a comment, then a BOM-free document
        query Q($o: String! = "acme", $n: [Int!]) @dir(a: 1) {
          a: repository(owner: $o, name: "web") {
            issues(first: 10, states: [OPEN, CLOSED], filterBy: {since: null}) { nodes { title } }
            ... on Repository { id }
            ...F @include(if: true)
          }
        }
        fragment F on Repository { name }
        mutation { addComment(input: {subjectId: "I_1", body: """block "quoted" \""" text"""}) { clientMutationId } }
        "#,
    )
    .unwrap();
    assert_eq!(d.operations.len(), 2);
    assert_eq!(d.fragments.len(), 1);
    let q = &d.operations[0];
    assert_eq!((q.ty, q.name.as_deref()), (OpType::Query, Some("Q")));
    assert_eq!(q.vars, vec![("o".into(), Some(Value::Str("acme".into()))), ("n".into(), None)]);
    let Selection::Field(f) = &q.selection[0] else { panic!() };
    assert_eq!((f.alias.as_deref(), f.name.as_str()), (Some("a"), "repository"));
    assert_eq!(f.args, vec![("owner".into(), Value::Var("o".into())), ("name".into(), Value::Str("web".into()))]);
    let inner = f.selection.as_ref().unwrap();
    assert!(matches!(&inner[1], Selection::Inline(Some(t), _) if t == "Repository"));
    assert_eq!(inner[2], Selection::Spread("F".into()));
    assert_eq!(d.operations[1].ty, OpType::Mutation);
    // The shorthand form is a query.
    assert_eq!(parse("{ viewer { login } }").unwrap().operations[0].ty, OpType::Query);
}

#[test]
fn strings_decode_escapes() {
    let d = parse(r#"{ f(a: "x\"\\\/\n\u0041\uD83D\uDE00") }"#).unwrap();
    let Selection::Field(f) = &d.operations[0].selection[0] else { panic!() };
    assert_eq!(f.args[0].1, Value::Str("x\"\\/\nA😀".into()));
}

#[test]
fn rejects_what_it_cannot_read_strictly() {
    for bad in [
        "",
        "   # only a comment",
        "type Query { a: Int }",
        "schema { query: Q }",
        "extend type Q { a: Int }",
        "{ a",
        "{ }",
        "query { a(b: ) }",
        "{ a(b: 01) }",
        "{ a(b: 1.) }",
        "{ a(b: 0x1) }",
        "{ a(b: 1e) }",
        "{ a(b: 1a) }",
        "{ a(b: -) }",
        "{ a(b: \"unterminated) }",
        "{ a(b: \"line\nbreak\") }",
        "{ a(b: \"nul\u{0}\") }",
        "{ a(b: \"\\uD800\") }",
        "{ a(b: \"\\u{41}\") }",
        "{ a(b: \"\\q\") }",
        "{ a(b: \"\"\"unterminated) }",
        "{ a .. }",
        "{ a } .",
        "fragment on on T { a }",
        "fragment F T { a }",
        "{ a(b: $v) } fragment F on T { c(d: 1) }\u{0}",
        "{ a } # comment with a line separator \u{2028} mutation { x }",
        "{ a } # nul \u{0}",
        "{ é }",
        "query ($v: Int = $w) { a }",
        "{ a } \u{85}",
    ] {
        assert!(parse(bad).is_err(), "{bad:?} parsed");
    }
}

#[test]
fn nesting_is_bounded() {
    let deep = format!("{}{}", "{ a ".repeat(MAX_DEPTH + 1), "}".repeat(MAX_DEPTH + 1));
    assert!(parse(&deep).is_err());
    let ok = format!("{}{}", "{ a ".repeat(MAX_DEPTH), "}".repeat(MAX_DEPTH));
    assert!(parse(&ok).is_ok());
    let list = format!("{{ a(b: {}1{}) }}", "[".repeat(200), "]".repeat(200));
    assert!(parse(&list).is_err());
}

fn name() -> impl Strategy<Value = String> {
    "[a-zA-Z_][a-zA-Z0-9_]{0,6}".prop_filter("not a keyword", |s| {
        !matches!(s.as_str(), "on" | "true" | "false" | "null" | "fragment" | "query" | "mutation" | "subscription")
    })
}

fn value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        name().prop_map(Value::Var),
        (-1000i64..1000).prop_map(|n| Value::Int(n.to_string())),
        "[ -~]{0,8}".prop_map(Value::Str),
        any::<bool>().prop_map(Value::Bool),
        Just(Value::Null),
        name().prop_map(Value::Enum),
    ];
    leaf.prop_recursive(3, 16, 4, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..3).prop_map(Value::List),
            proptest::collection::vec((name(), inner), 0..3).prop_map(Value::Object),
        ]
    })
}

fn selection() -> impl Strategy<Value = Selection> {
    let field = (proptest::option::of(name()), name(), proptest::collection::vec((name(), value()), 0..2))
        .prop_map(|(alias, name, args)| Selection::Field(Field { alias, name, args, selection: None }));
    field.prop_recursive(4, 24, 3, |inner| {
        prop_oneof![
            (proptest::option::of(name()), name(), proptest::collection::vec(inner.clone(), 1..3))
                .prop_map(|(alias, name, s)| Selection::Field(Field { alias, name, args: vec![], selection: Some(s) })),
            (proptest::option::of(name()), proptest::collection::vec(inner, 1..3))
                .prop_map(|(on, s)| Selection::Inline(on, s)),
            name().prop_map(Selection::Spread),
        ]
    })
}

fn print_value(v: &Value) -> String {
    match v {
        Value::Var(n) => format!("${n}"),
        Value::Int(s) | Value::Float(s) | Value::Enum(s) => s.clone(),
        Value::Str(s) => serde_json::to_string(s).unwrap(),
        Value::Block(s) => format!("\"\"\"{s}\"\"\""),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".into(),
        Value::List(l) => format!("[{}]", l.iter().map(print_value).collect::<Vec<_>>().join(", ")),
        Value::Object(o) => {
            format!("{{{}}}", o.iter().map(|(k, v)| format!("{k}: {}", print_value(v))).collect::<Vec<_>>().join(" "))
        }
    }
}

fn print_sel(s: &[Selection]) -> String {
    let items: Vec<String> = s
        .iter()
        .map(|x| match x {
            Selection::Field(f) => {
                let mut o = String::new();
                if let Some(a) = &f.alias {
                    o += &format!("{a}: ");
                }
                o += &f.name;
                if !f.args.is_empty() {
                    let a: Vec<String> = f.args.iter().map(|(k, v)| format!("{k}: {}", print_value(v))).collect();
                    o += &format!("({})", a.join(", "));
                }
                if let Some(s) = &f.selection {
                    o += &format!(" {}", print_sel(s));
                }
                o
            }
            Selection::Spread(n) => format!("...{n}"),
            Selection::Inline(Some(t), s) => format!("... on {t} {}", print_sel(s)),
            Selection::Inline(None, s) => format!("... {}", print_sel(s)),
        })
        .collect();
    format!("{{ {} }}", items.join(" "))
}

proptest! {
    /// Printing a generated operation and parsing it back gives the same
    /// tree (the parser reads what a conforming printer wrote).
    #[test]
    fn print_then_parse_round_trips(
        ty in prop_oneof![Just(OpType::Query), Just(OpType::Mutation)],
        name in proptest::option::of(name()),
        sel in proptest::collection::vec(selection(), 1..4),
    ) {
        let kw = if ty == OpType::Query { "query" } else { "mutation" };
        let src = format!("{kw} {} {}", name.clone().unwrap_or_default(), print_sel(&sel));
        let d = parse(&src).unwrap();
        prop_assert_eq!(d.operations, vec![Operation { ty, name, vars: vec![], selection: sel }]);
    }

    /// Arbitrary text never panics the parser.
    #[test]
    fn arbitrary_text_never_panics(s in "\\PC{0,200}") {
        let _ = parse(&s);
    }

    /// Token soup from the GraphQL alphabet never panics either.
    #[test]
    fn token_soup_never_panics(parts in proptest::collection::vec(
        prop_oneof![
            Just("{"), Just("}"), Just("("), Just(")"), Just(":"), Just("$"), Just("..."), Just("["), Just("]"),
            Just("query"), Just("mutation"), Just("fragment"), Just("on"), Just("a"), Just("\"s\""), Just("1"),
            Just("@d"), Just("="), Just("!"), Just("\"\"\"b\"\"\""), Just("#c\n"),
        ], 0..40)) {
        let _ = parse(&parts.join(" "));
    }
}

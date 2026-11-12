use std::collections::HashSet;

use rune_chain_core::{Tool, ToolError};

use crate::{
    Base64Decode, Base64Encode, CaesarBrute, EntropyScore, ExtractStrings, ExtractStringsFromHex,
    HexDecode, HexEncode, Sha256, XorBrute, analysis, cipher, encoding, hashing,
};

fn run(tool: &dyn Tool, input: &str) -> Result<String, ToolError> {
    tokio_test::block_on(tool.run(input))
}

fn all_tools() -> Vec<Box<dyn Tool>> {
    vec![
        Box::new(HexEncode),
        Box::new(HexDecode),
        Box::new(Base64Encode),
        Box::new(Base64Decode),
        Box::new(Sha256),
        Box::new(EntropyScore),
        Box::new(ExtractStrings),
        Box::new(ExtractStringsFromHex),
        Box::new(CaesarBrute),
        Box::new(XorBrute),
    ]
}

// ── encoding ──────────────────────────────────────────────────────────────────

#[test]
fn hex_round_trip_including_unicode() {
    for s in ["", "hello", "héllo wörld ✓", "\0\x01\x7f"] {
        assert_eq!(encoding::hex_decode(&encoding::hex_encode(s)).unwrap(), s);
    }
}

#[test]
fn hex_decode_rejects_bad_input() {
    assert!(encoding::hex_decode("abc").is_err(), "odd length");
    assert!(encoding::hex_decode("zz").is_err(), "non-hex digit");
    assert!(encoding::hex_decode("ff").is_err(), "not UTF-8");
}

#[test]
fn base64_rfc4648_vectors() {
    // RFC 4648 §10 test vectors.
    for (plain, encoded) in [
        ("", ""),
        ("f", "Zg=="),
        ("fo", "Zm8="),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg=="),
        ("fooba", "Zm9vYmE="),
        ("foobar", "Zm9vYmFy"),
    ] {
        assert_eq!(encoding::base64_encode(plain), encoded);
        assert_eq!(encoding::base64_decode(encoded).unwrap(), plain);
    }
}

#[test]
fn base64_decode_rejects_bad_input() {
    assert!(encoding::base64_decode("!!!!").is_err());
    // "/w==" decodes to the single byte 0xFF, which is not UTF-8.
    assert!(encoding::base64_decode("/w==").is_err());
}

// ── hashing ───────────────────────────────────────────────────────────────────

#[test]
fn sha256_known_answers() {
    // FIPS 180-2 examples.
    assert_eq!(
        hashing::sha256(""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        hashing::sha256("abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

// ── analysis ──────────────────────────────────────────────────────────────────

#[test]
fn entropy_bounds() {
    assert!(analysis::entropy_score("").abs() < f64::EPSILON);
    assert!(analysis::entropy_score("zzzz").abs() < f64::EPSILON);
    // Two equally likely symbols carry exactly one bit each.
    assert!((analysis::entropy_score("abababab") - 1.0).abs() < 1e-9);
    // Four equally likely symbols carry two bits each.
    assert!((analysis::entropy_score("abcdabcd") - 2.0).abs() < 1e-9);
}

#[test]
fn extract_strings_filters_short_runs() {
    let found = analysis::extract_strings("abc\0longer\x01run\x02four");
    assert_eq!(found, vec!["longer".to_string(), "four".to_string()]);
}

#[test]
fn extract_strings_from_hex_decodes_first() {
    let hex = encoding::hex_encode("\x00\x01secret_key\x02\x03");
    assert_eq!(
        analysis::extract_strings_from_hex(&hex),
        vec!["secret_key".to_string()]
    );
    assert_eq!(
        analysis::extract_strings_from_hex("not hex"),
        vec!["error: invalid hex input".to_string()]
    );
}

// ── cipher ────────────────────────────────────────────────────────────────────

#[test]
fn caesar_brute_finds_plaintext() {
    let candidates = cipher::caesar_brute("Khoor, Zruog!");
    assert!(
        candidates.iter().any(|c| c.ends_with("Hello, World!")),
        "{candidates:?}"
    );
    let shifts: HashSet<_> = candidates.iter().map(|c| c[..2].to_string()).collect();
    assert_eq!(shifts.len(), candidates.len(), "one line per shift");
}

#[test]
fn xor_brute_ranks_true_key_first() {
    let plain = b"the quick brown fox jumps over the lazy dog";
    let cipher_bytes: Vec<u8> = plain.iter().map(|b| b ^ 0x5A).collect();
    let results = cipher::xor_brute(&rune_hex::encode(&cipher_bytes));
    assert!(results.len() <= 5);
    assert!(results[0].starts_with("key=0x5A "), "{results:?}");
    assert!(results[0].ends_with("the quick brown fox jumps over the lazy dog"));
}

#[test]
fn xor_brute_reports_invalid_hex() {
    assert_eq!(
        cipher::xor_brute("xyz"),
        vec!["error: invalid hex input".to_string()]
    );
}

// ── Tool wrappers ─────────────────────────────────────────────────────────────

#[test]
fn tool_names_are_unique_identifiers() {
    let tools = all_tools();
    let names: HashSet<_> = tools.iter().map(|t| t.name().to_string()).collect();
    assert_eq!(names.len(), tools.len());
    for tool in &tools {
        assert!(!tool.name().contains(' '), "{}", tool.name());
        assert_ne!(tool.description(), "");
        let def = tool.function_definition();
        assert_eq!(def.name, tool.name());
        assert_eq!(def.parameters["required"][0], "input");
    }
}

#[test]
fn encoding_tools_round_trip() {
    let hex = run(&HexEncode, "rune").unwrap();
    assert_eq!(hex, "72756e65");
    assert_eq!(run(&HexDecode, &hex).unwrap(), "rune");

    let b64 = run(&Base64Encode, "rune").unwrap();
    assert_eq!(b64, "cnVuZQ==");
    assert_eq!(run(&Base64Decode, &b64).unwrap(), "rune");
}

#[test]
fn decode_tools_map_errors_to_invalid_input() {
    assert!(matches!(
        run(&HexDecode, "zz"),
        Err(ToolError::InvalidInput(_))
    ));
    assert!(matches!(
        run(&Base64Decode, "@@@"),
        Err(ToolError::InvalidInput(_))
    ));
    assert!(matches!(
        run(&ExtractStringsFromHex, "zz"),
        Err(ToolError::InvalidInput(m)) if m.starts_with("error:")
    ));
}

#[test]
fn analysis_tools_format_output() {
    assert_eq!(run(&Sha256, "abc").unwrap(), hashing::sha256("abc"));
    let score: f64 = run(&EntropyScore, "abababab").unwrap().parse().unwrap();
    assert!((score - 1.0).abs() < 1e-9);
    assert_eq!(
        run(&ExtractStrings, "alpha\0beta\0gam").unwrap(),
        "alpha\nbeta"
    );
    let hex = encoding::hex_encode("\x01first\x02second");
    assert_eq!(run(&ExtractStringsFromHex, &hex).unwrap(), "first\nsecond");
}

#[test]
fn cipher_tools_join_candidates_by_line() {
    let out = run(&CaesarBrute, "khoor").unwrap();
    assert_eq!(out.lines().count(), cipher::caesar_brute("khoor").len());
    assert!(out.lines().any(|l| l.ends_with("hello")));

    let cipher_hex = rune_hex::encode(
        b"attack at dawn"
            .iter()
            .map(|b| b ^ 0x13)
            .collect::<Vec<_>>(),
    );
    let out = run(&XorBrute, &cipher_hex).unwrap();
    assert!(out.lines().next().unwrap().ends_with("attack at dawn"));
}

// ── trait contract ────────────────────────────────────────────────────────────

#[test]
fn every_tool_passes_the_tool_contract() {
    use rune_chain_core::testing::{check_tool, check_tool_rejects};

    let hex = encoding::hex_encode("hello world");
    for tool in all_tools() {
        let valid = match tool.name() {
            "hex_decode" | "extract_strings_from_hex" | "xor_brute" => hex.as_str(),
            "base64_decode" => "aGVsbG8=",
            _ => "hello world",
        };
        tokio_test::block_on(check_tool(tool.as_ref(), valid))
            .unwrap_or_else(|e| panic!("{}: {e}", tool.name()));
    }
    for (tool, invalid) in [
        (&HexDecode as &dyn Tool, "zz"),
        (&Base64Decode, "!!!"),
        (&ExtractStringsFromHex, "xyz"),
    ] {
        tokio_test::block_on(check_tool_rejects(tool, invalid)).unwrap();
    }
}

// ── input handling ────────────────────────────────────────────────────────────

#[test]
fn function_call_arguments_are_unwrapped() {
    assert_eq!(
        run(&HexEncode, r#"{"input":"hello"}"#).unwrap(),
        "68656c6c6f"
    );
    assert_eq!(run(&HexEncode, "hello").unwrap(), "68656c6c6f");
    assert_eq!(
        run(&Sha256, r#" {"input":""}"#).unwrap(),
        crate::hashing::sha256("")
    );
}

#[test]
fn wrong_argument_shapes_are_rejected() {
    for bad in [
        r#"{"input":1}"#,
        r#"{"input":"x","extra":true}"#,
        r#"{"path":"/etc/passwd"}"#,
        "{not json",
    ] {
        for tool in all_tools() {
            assert!(
                matches!(run(tool.as_ref(), bad), Err(ToolError::InvalidInput(_))),
                "{} accepted {bad}",
                tool.name()
            );
        }
    }
}

#[test]
fn oversized_inputs_are_rejected() {
    let big = "a".repeat(crate::input::MAX_INPUT_BYTES + 1);
    for tool in all_tools() {
        assert!(run(tool.as_ref(), &big).is_err(), "{}", tool.name());
    }
    let caesar = "a".repeat(crate::input::MAX_CAESAR_INPUT_BYTES + 1);
    assert!(run(&CaesarBrute, &caesar).is_err());
    let wrapped = serde_json::json!({ "input": caesar }).to_string();
    assert!(run(&CaesarBrute, &wrapped).is_err());
    let xor = "ab".repeat(crate::input::MAX_XOR_INPUT_BYTES);
    assert!(run(&XorBrute, &xor).is_err());
}

#[test]
fn invalid_hex_is_an_error_not_a_result() {
    assert!(matches!(
        run(&XorBrute, "zz"),
        Err(ToolError::InvalidInput(_))
    ));
    assert!(matches!(
        run(&ExtractStringsFromHex, "zz"),
        Err(ToolError::InvalidInput(_))
    ));
    // A blob whose only string is "error: ..." is data, not a failure.
    let hex = encoding::hex_encode("error: invalid hex input");
    assert_eq!(
        run(&ExtractStringsFromHex, &hex).unwrap(),
        "error: invalid hex input"
    );
}

#[test]
fn schemas_are_closed_and_validate_well_formed_calls() {
    for tool in all_tools() {
        let def = tool.function_definition();
        assert!(def.has_valid_name());
        let ok = rune_chain_core::ToolCall::new("1", tool.name(), r#"{"input":"41"}"#);
        ok.validate(&def).unwrap();
        let extra = rune_chain_core::ToolCall::new("1", tool.name(), r#"{"input":"41","x":1}"#);
        assert!(extra.validate(&def).is_err());
        let missing = rune_chain_core::ToolCall::new("1", tool.name(), "{}");
        assert!(missing.validate(&def).is_err());
    }
}

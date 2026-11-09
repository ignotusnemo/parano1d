// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use std::{collections::BTreeMap, path::Path};

use noid_poseidon2b::primitives::Address;
use noid_tx::experimental_object::{integer_program as native, ObjectOpening, OPENING_BYTES};
use serde_json::json;

use crate::{
    compile,
    syntax::{Expr, ExprKind, Op, Statement, Value},
    verify::{self, Verdict},
    CompiledContract,
};

const BUDGET: &str = include_str!("../examples/budget.pruv");
const INSTRUCTIONS: &str = include_str!("../examples/instructions.pruv");

fn parameters() -> serde_json::Value {
    json!({
        "spending_key": Address([1; 32]).to_bech32(),
        "recovery_key": Address([2; 32]).to_bech32(),
        "recipient": Address([3; 32]).to_bech32(),
        "recover_at": "1000", "budget": "1000000", "max_fee": "100", "max_payment": "10000",
    })
}

fn source(body: &str, ensures: &str) -> String {
    let start = BUDGET.find("    call {").unwrap();
    format!("{}    call {{ {body} }}\n{ensures}\n}}", &BUDGET[..start])
}

#[test]
fn budget_compiles_to_existing_abi_and_canonical_definition() {
    let contract = compile(BUDGET, &parameters()).unwrap();
    assert_eq!(contract.instructions, 3);
    assert_eq!(native::unpack_state(contract.opening.state), [1000000, 0]);
    let bytes = contract.opening.to_bytes().unwrap();
    assert_eq!(bytes.len(), OPENING_BYTES);
    assert_eq!(ObjectOpening::from_bytes(&bytes).unwrap(), contract.opening);
    let definition = contract.definition();
    assert_eq!(definition["kind"], "custom_program");
    assert_eq!(definition["definition"]["state"], json!(["1000000", "0"]));
    assert_eq!(
        definition["definition"]["program"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    assert_eq!(definition["definition"]["recovery_can_close"], true);
    assert_eq!(contract.opening.program[3..], native::EMPTY_PROGRAM[3..]);
    let context = native::Context {
        payout: 200,
        fee: 3,
        ..Default::default()
    };
    let next = native::execute(&contract.opening.program, contract.opening.state, context).unwrap();
    assert_eq!(native::unpack_state(next), [999797, 1]);
    assert!(native::execute(
        &contract.opening.program,
        contract.opening.state,
        native::Context {
            payout: 1000000,
            fee: 1,
            ..context
        }
    )
    .is_err());
    assert_eq!(
        native::execute(
            &contract.opening.program,
            contract.opening.state,
            native::Context {
                terminal: true,
                payout: u64::MAX,
                fee: u64::MAX,
                ..context
            }
        )
        .unwrap(),
        contract.opening.state
    );
}

#[test]
fn line_comments_preserve_statements_across_line_endings() {
    let plain = source(
        "when !terminal { remaining -= payout + fee; calls += 1; }",
        "",
    );
    let expected = compile(&plain, &parameters()).unwrap().opening;
    let commented = source(
        "when !terminal {\n    // Update the balance.\n    remaining -= payout + fee;\n    calls += 1;\n}",
        "",
    );
    for ending in ["\n", "\r\n", "\r"] {
        let whole_file = commented.replace('\n', ending);
        let mixed = commented.replace(
            "// Update the balance.\n",
            &format!("// Update the balance.{ending}"),
        );
        for text in [whole_file, mixed] {
            let contract = compile(&text, &parameters()).unwrap();
            assert_eq!(contract.opening, expected, "line ending {ending:?}");
            let next = native::execute(
                &contract.opening.program,
                contract.opening.state,
                native::Context {
                    payout: 200,
                    fee: 3,
                    ..Default::default()
                },
            )
            .unwrap();
            assert_eq!(native::unpack_state(next), [999797, 1]);
        }
    }
}

#[test]
fn diagnostics_keep_line_and_column_across_line_endings() {
    let text = source("calls += 1;\n    remaining = unknown;", "");
    let expected = compile(&text, &parameters()).unwrap_err();
    assert!(expected.message.contains("unknown name"));
    for ending in ["\n", "\r\n", "\r"] {
        let error = compile(&text.replace('\n', ending), &parameters()).unwrap_err();
        assert_eq!(error, expected, "line ending {ending:?}");
    }
}

#[test]
fn parameters_are_exact_typed_and_complete() {
    for value in [
        json!(100),
        json!("01"),
        json!("-1"),
        json!("1.0"),
        json!("18446744073709551616"),
        json!(true),
    ] {
        let mut params = parameters();
        params["budget"] = value;
        assert!(compile(BUDGET, &params).is_err());
    }
    let mut params = parameters();
    params["budget"] = json!(u64::MAX.to_string());
    let contract = compile(BUDGET, &params).unwrap();
    assert_eq!(
        contract.definition()["definition"]["state"][0],
        u64::MAX.to_string()
    );
    params["spending_key"] = json!("not-an-address");
    assert!(compile(BUDGET, &params).is_err());
    let mut params = parameters();
    params.as_object_mut().unwrap().remove("budget");
    assert!(compile(BUDGET, &params)
        .unwrap_err()
        .message
        .contains("missing parameter"));
    let mut params = parameters();
    params["budgte"] = json!("1000");
    assert!(compile(BUDGET, &params)
        .unwrap_err()
        .message
        .contains("unknown parameter"));
}

#[test]
fn policy_never_invents_permissions_or_addresses() {
    for text in [
        BUDGET.replace("claim_can_close = false;", ""),
        BUDGET.replace("claim_can_close = false;", "claim_can_clsoe = false;"),
        BUDGET.replace(
            "claim_can_close = false;",
            "claim_can_close = false; claim_can_close = true;",
        ),
        BUDGET.replace("claim_can_close = false;", "claim_can_close = 0;"),
        BUDGET.replace("deadline_height = recover_at;", "deadline_height = height;"),
        BUDGET.replace(
            "claim_authority = spending_key;",
            "claim_authority = \"bad\";",
        ),
    ] {
        assert!(compile(&text, &parameters()).is_err(), "{text}");
    }
}

#[test]
fn resource_type_and_syntax_errors_are_reported() {
    let cases = [
        (source(&"calls += 1;".repeat(17), ""), "16 instructions"),
        (
            BUDGET.replace(
                "state calls: u64 = 0;",
                "state calls: u64 = 0; state extra: u64 = 0;",
            ),
            "two persistent",
        ),
        (source("remaining = true;", ""), "requires u64"),
        (source("when remaining { calls += 1; }", ""), "bool"),
        (source("require remaining;", ""), "bool"),
        (source("height = 5;", ""), "not a state variable"),
        (source("remaining = unknown;", ""), "unknown name"),
        (source("remaining = old(remaining);", ""), "ensures only"),
        (
            source("remaining = 18446744073709551616;", ""),
            "exceeds u64",
        ),
        (source("remaining = 01;", ""), "leading zeroes"),
        (
            source("remaining = 18446744073709551615 + 1;", ""),
            "overflows",
        ),
        (source("remaining = 0 - 1;", ""), "underflows"),
        (source("while true { calls += 1; }", ""), "expected '='"),
        (format!("{} trailing", source("", "")), "after contract"),
        (source("calls += 1", ""), "expected ';'"),
    ];
    for (text, expected) in cases {
        let error = compile(&text, &parameters()).unwrap_err();
        assert!(
            error.message.contains(expected),
            "{error}: expected {expected}"
        );
        assert!(error.line > 0);
    }
    assert!(compile(&" ".repeat(crate::MAX_SOURCE_BYTES + 1), &json!({})).is_err());
    let text = source(&format!("calls = {};", vec!["calls"; 1000].join(" + ")), "");
    assert!(compile(&text, &parameters())
        .unwrap_err()
        .message
        .contains("nesting"));
    let text = source(
        &format!(
            "{}calls += 1;{}",
            "when !terminal {".repeat(100),
            "}".repeat(100)
        ),
        "",
    );
    assert!(compile(&text, &parameters())
        .unwrap_err()
        .message
        .contains("nesting"));
}

#[test]
fn aliases_constants_and_evaluation_order_are_stable() {
    let text = source("remaining = remaining + 1; calls = remaining + calls;", "").replace(
        "state remaining: u64 = budget;",
        "const initial: u64 = budget - 1; state remaining: u64 = initial;",
    );
    let contract = compile(&text, &parameters()).unwrap();
    let result = native::execute(
        &contract.opening.program,
        contract.opening.state,
        native::Context::default(),
    )
    .unwrap();
    assert_eq!(native::unpack_state(result), [1000000, 1000000]);
    let renamed = text
        .replace("remaining", "balance")
        .replace("calls", "counter");
    assert_eq!(
        compile(&renamed, &parameters()).unwrap().opening,
        contract.opening
    );
    for text in [
        BUDGET.replace("state calls: u64 = 0;", "state remaining: u64 = 0;"),
        BUDGET.replace("state calls: u64 = 0;", "state height: u64 = 0;"),
        BUDGET.replace("state calls: u64 = 0;", "state calls: bool = false;"),
    ] {
        assert!(compile(&text, &parameters()).is_err());
    }
}

fn evaluate(
    expr: &Expr,
    contract: &CompiledContract,
    states: &[u64; 2],
    context: native::Context,
) -> Result<Value, ()> {
    let u64_value = |value: Value| match value {
        Value::U64(value) => Ok(value),
        _ => Err(()),
    };
    match &expr.kind {
        ExprKind::Value(value) => Ok(value.clone()),
        ExprKind::Name(name) => {
            if let Some(value) = contract.env.values.get(name) {
                return Ok(value.clone());
            }
            if let Some(register) = contract.env.states.get(name) {
                return Ok(Value::U64(states[*register as usize]));
            }
            Ok(match name.as_str() {
                "height" => Value::U64(context.height),
                "fee" => Value::U64(context.fee),
                "payout" => Value::U64(context.payout),
                "retained" => Value::U64(context.retained),
                "input_amount" => Value::U64(context.input_amount),
                "before_deadline" => Value::Bool(context.before_deadline),
                "after_deadline" => Value::Bool(!context.before_deadline),
                "terminal" => Value::Bool(context.terminal),
                "has_payout" => Value::Bool(context.has_payout),
                "input_creation_id" => Value::U64(context.input_creation_id),
                "input_slot" => Value::U64(context.input_slot.into()),
                "retained_slot" => Value::U64(context.retained_slot.into()),
                "payout_slot" => Value::U64(context.payout_slot.into()),
                "payout_owner0" => Value::U64(context.payout_owner[0]),
                "payout_owner1" => Value::U64(context.payout_owner[1]),
                "payout_owner2" => Value::U64(context.payout_owner[2]),
                "payout_owner3" => Value::U64(context.payout_owner[3]),
                _ => panic!("unknown name {name}"),
            })
        }
        ExprKind::Not(inner) => match evaluate(inner, contract, states, context)? {
            Value::Bool(value) => Ok(Value::Bool(!value)),
            _ => Err(()),
        },
        ExprKind::Binary(op, left, right) => {
            let left = evaluate(left, contract, states, context)?;
            let right = evaluate(right, contract, states, context)?;
            if let (Value::Bool(left), Value::Bool(right)) = (&left, &right) {
                return Ok(Value::Bool(match op {
                    Op::Equal => left == right,
                    Op::NotEqual => left != right,
                    _ => return Err(()),
                }));
            }
            let (left, right) = (u64_value(left)?, u64_value(right)?);
            Ok(match op {
                Op::Add => Value::U64(left.checked_add(right).ok_or(())?),
                Op::Subtract => Value::U64(left.checked_sub(right).ok_or(())?),
                Op::Min => Value::U64(left.min(right)),
                Op::Max => Value::U64(left.max(right)),
                Op::Equal => Value::Bool(left == right),
                Op::NotEqual => Value::Bool(left != right),
                Op::Less => Value::Bool(left < right),
                Op::LessEqual => Value::Bool(left <= right),
                Op::Greater => Value::Bool(left > right),
                Op::GreaterEqual => Value::Bool(left >= right),
            })
        }
        ExprKind::Old(_) => Err(()),
    }
}

fn interpret(
    statements: &[Statement],
    contract: &CompiledContract,
    states: &mut [u64; 2],
    context: native::Context,
) -> Result<(), ()> {
    for statement in statements {
        match statement {
            Statement::Assign(name, expr, _) => {
                let Value::U64(value) = evaluate(expr, contract, states, context)? else {
                    return Err(());
                };
                states[contract.env.states[name] as usize] = value;
            }
            Statement::Require(expr) => {
                if !matches!(
                    evaluate(expr, contract, states, context)?,
                    Value::Bool(true)
                ) {
                    return Err(());
                }
            }
            Statement::When(condition, statements) => {
                let Value::Bool(condition) = evaluate(condition, contract, states, context)? else {
                    return Err(());
                };
                if condition {
                    interpret(statements, contract, states, context)?;
                }
            }
        }
    }
    Ok(())
}

#[test]
fn source_and_native_execution_agree_at_boundaries_and_under_branching() {
    let bodies = [
        "remaining -= payout + fee; calls += 1;",
        "when !terminal { remaining -= payout + fee; calls += 1; }",
        "when before_deadline { when !terminal { remaining -= payout + fee; calls += 1; } }",
        "when after_deadline { when terminal { calls = remaining; } }",
        "when remaining > 0 { remaining -= 1; calls += 1; }",
        "when !(remaining == 0) { remaining -= 1; calls += 1; }",
        "remaining = min(remaining + fee, calls);",
        "remaining = max(remaining - fee, payout + calls);",
        "require remaining <= calls; remaining += payout;",
        "require remaining >= calls; remaining -= payout;",
        "require remaining == calls; remaining = 5;",
        "require remaining != calls; calls = max(height, input_amount);",
        "require remaining < calls; remaining = retained;",
        "require remaining > calls; calls = input_creation_id;",
        "when true { remaining = payout_owner3; } when false { remaining += fee; }",
        "when before_deadline == !terminal { remaining = input_slot + retained_slot; }",
        "remaining = (remaining + fee) - (calls + payout);",
        "remaining = remaining + 2; require remaining == 3;",
        "require 2 != 3; calls += 1;",
        "require 2 == 3; calls += 1;",
        "calls = 5; when terminal { when has_payout { calls += 1; } }",
    ];
    let edges = [
        0,
        1,
        2,
        3,
        100,
        1000000,
        u32::MAX as u64,
        1 << 53,
        u64::MAX - 1,
        u64::MAX,
    ];
    let mut random = 0x1234_5678_9abc_def0u64;
    for body in bodies {
        let contract = compile(&source(body, ""), &parameters())
            .unwrap_or_else(|error| panic!("{body}: {error}"));
        for left in edges {
            for right in edges {
                for flags in 0..8 {
                    random ^= random << 13;
                    random ^= random >> 7;
                    random ^= random << 17;
                    let context = native::Context {
                        height: random,
                        fee: right,
                        payout: left,
                        retained: random,
                        input_amount: left,
                        before_deadline: flags & 1 != 0,
                        terminal: flags & 2 != 0,
                        has_payout: flags & 4 != 0,
                        payout_owner: [random; 4],
                        input_creation_id: random,
                        input_slot: random as u32,
                        retained_slot: (random >> 32) as u32,
                        payout_slot: 0,
                    };
                    let mut expected = [left, right];
                    let expected =
                        interpret(&contract.source.body, &contract, &mut expected, context)
                            .map(|_| expected);
                    let actual = native::execute(
                        &contract.opening.program,
                        native::pack_state([left, right]),
                        context,
                    )
                    .map(native::unpack_state)
                    .map_err(|_| ());
                    assert_eq!(actual, expected, "{body}: {left}, {right}, flags {flags}");
                }
            }
        }
    }
}

#[test]
fn scratch_pressure_is_a_compile_error() {
    let body = "when remaining > 0 { when calls > 0 { remaining = min(remaining + fee, calls + payout); } }";
    assert!(compile(&source(body, ""), &parameters())
        .unwrap_err()
        .message
        .contains("scratch"));
}

#[test]
fn exact_instruction_limit_and_empty_program_are_usable() {
    let full = compile(&source(&"calls += 1;".repeat(16), ""), &parameters()).unwrap();
    assert_eq!(full.instructions, 16);
    let next = native::execute(
        &full.opening.program,
        full.opening.state,
        native::Context::default(),
    )
    .unwrap();
    assert_eq!(native::unpack_state(next), [1000000, 16]);
    let empty = compile(&source("", ""), &parameters()).unwrap();
    assert_eq!(empty.instructions, 0);
    assert_eq!(empty.opening.program, native::EMPTY_PROGRAM);
    assert_eq!(empty.definition()["definition"]["program"], json!([]));
}

#[test]
fn instruction_example_covers_all_ten_native_opcodes() {
    let contract = compile(INSTRUCTIONS, &parameters()).unwrap();
    assert_eq!(contract.instructions, 13);
    let mut seen = std::collections::BTreeSet::new();
    for fields in contract.opening.program {
        seen.insert(native::Instruction::from_fields(fields).unwrap().opcode as u8);
    }
    assert_eq!(seen.len(), native::OPCODE_COUNT);
    let context = native::Context {
        input_amount: 10000,
        payout: 1000,
        fee: 5,
        retained: 8995,
        ..Default::default()
    };
    let next = native::execute(&contract.opening.program, contract.opening.state, context).unwrap();
    assert_eq!(native::unpack_state(next), [8995, 2]);
    let next = native::execute(&contract.opening.program, next, context).unwrap();
    assert_eq!(native::unpack_state(next), [8995, 3]);
}

#[test]
fn parameter_files_reject_duplicate_names_and_trailing_data() {
    assert_eq!(
        crate::parse_parameters(r#"{"budget":"10"}"#).unwrap(),
        json!({"budget":"10"})
    );
    for text in [
        r#"{"budget":"10","budget":"20"}"#,
        r#"{"budget":"10"} {}"#,
        "[]",
        "null",
        "1",
    ] {
        assert!(crate::parse_parameters(text).is_err(), "{text}");
    }
    assert!(crate::parse_parameters(&" ".repeat(crate::MAX_SOURCE_BYTES + 1)).is_err());
}

#[cfg(unix)]
#[test]
fn solver_errors_partial_answers_and_timeouts_fail_closed() {
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        time::{Duration, Instant},
    };

    let directory = tempfile::tempdir().unwrap();
    let contract = compile(BUDGET, &parameters()).unwrap();
    let cases = [
        ("sat\\nunsat\\n", 0, Some(Verdict::Verified)),
        ("sat\\nsat\\n", 0, Some(Verdict::Counterexample)),
        ("unsat\\nunsat\\n", 0, Some(Verdict::Infeasible)),
        ("unknown\\nunsat\\n", 0, None),
        ("sat\\n", 0, None),
        ("unsat\\nsat\\n", 0, None),
        ("sat\\nunsat\\n", 1, None),
        ("error\\nsat\\nunsat\\n", 0, None),
    ];
    for (index, (output, exit, expected)) in cases.into_iter().enumerate() {
        let solver = directory.path().join(format!("solver with spaces {index}"));
        fs::write(
            &solver,
            format!("#!/bin/sh\ncat > /dev/null\nprintf '{output}'\nexit {exit}\n"),
        )
        .unwrap();
        fs::set_permissions(&solver, fs::Permissions::from_mode(0o700)).unwrap();
        let result = verify::verify(&contract, &solver);
        match expected {
            Some(expected) => assert_eq!(result.unwrap(), expected),
            None => assert!(result.is_err(), "accepted {output}, exit {exit}"),
        }
    }
    let solver = directory.path().join("slow solver");
    fs::write(&solver, "#!/bin/sh\ncat > /dev/null\nexec sleep 10\n").unwrap();
    fs::set_permissions(&solver, fs::Permissions::from_mode(0o700)).unwrap();
    let started = Instant::now();
    let result = verify::verify_with_limit(&contract, &solver, Duration::from_millis(100));
    assert!(result.unwrap_err().message.contains("wall limit"));
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn malformed_inputs_return_errors_without_panicking() {
    let mut seed = 0x7162_bfa0_98e3_c451_u64;
    let alphabet = b"abc_019{}();:=!<>+-/,\"\\ \n";
    for length in 0..256 {
        for _ in 0..8 {
            let mut text = String::from("contract Broken { ");
            for _ in 0..length {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                text.push(alphabet[seed as usize % alphabet.len()] as char);
            }
            let result = std::panic::catch_unwind(|| compile(&text, &json!({})));
            assert!(result.is_ok(), "parser panic on {text:?}");
        }
    }
}

#[test]
fn bool_bindings_constants_and_token_limits_are_enforced() {
    let text = source(
        "when enabled { remaining = 1; } when disabled { remaining = 2; }",
        "",
    )
    .replace(
        "param budget: u64;",
        "param budget: u64; param enabled: bool; const disabled: bool = !enabled;",
    );
    for enabled in [false, true] {
        let mut params = parameters();
        params["enabled"] = json!(enabled);
        let contract = compile(&text, &params).unwrap();
        let state = native::execute(
            &contract.opening.program,
            contract.opening.state,
            native::Context::default(),
        )
        .unwrap();
        assert_eq!(
            native::unpack_state(state),
            [if enabled { 1 } else { 2 }, 0]
        );
    }
    let mut params = parameters();
    params["enabled"] = json!("true");
    assert!(compile(&text, &params)
        .unwrap_err()
        .message
        .contains("JSON bool"));
    let too_many_tokens = source(&"calls += 1;".repeat(2050), "");
    assert!(too_many_tokens.len() < crate::MAX_SOURCE_BYTES);
    assert!(compile(&too_many_tokens, &parameters())
        .unwrap_err()
        .message
        .contains("8192 tokens"));
}

#[test]
fn every_context_operand_and_generated_expression_matches_native_execution() {
    let numbers = [
        "height",
        "fee",
        "payout",
        "retained",
        "input_amount",
        "input_creation_id",
        "input_slot",
        "retained_slot",
        "payout_slot",
        "payout_owner0",
        "payout_owner1",
        "payout_owner2",
        "payout_owner3",
        "remaining",
        "calls",
        "0",
        "1",
        "2",
        "18446744073709551615",
    ];
    let mut bodies = Vec::new();
    for name in numbers {
        bodies.push(format!("remaining = {name}; calls = {name};"));
    }
    for name in [
        "before_deadline",
        "after_deadline",
        "terminal",
        "has_payout",
    ] {
        bodies.push(format!(
            "when {name} {{ remaining = fee; }} when !{name} {{ remaining = payout; }}"
        ));
    }
    for (index, left) in numbers.into_iter().enumerate() {
        for right in numbers.into_iter().take(15) {
            for operation in ["+", "-", "min", "max"] {
                let value = if operation == "min" || operation == "max" {
                    format!("{operation}({left}, {right})")
                } else {
                    format!("{left} {operation} {right}")
                };
                bodies.push(format!("remaining = {value};"));
            }
            if index < 15 {
                for operation in ["==", "!=", "<", "<=", ">", ">="] {
                    bodies.push(format!("require {left} {operation} {right}; calls += 1;"));
                    bodies.push(format!("when {left} {operation} {right} {{ calls += 1; }}"));
                }
            }
        }
    }
    let edges = [0, 1, 2, (1u64 << 53) + 1, u64::MAX - 1, u64::MAX];
    let mut random = 0xd148_2c7f_a10e_b983_u64;
    let mut comparisons = 0;
    for body in bodies {
        let contract = compile(&source(&body, ""), &parameters())
            .unwrap_or_else(|error| panic!("{body}: {error}"));
        for value in edges {
            for flags in 0..8 {
                random ^= random << 13;
                random ^= random >> 7;
                random ^= random << 17;
                let context = native::Context {
                    height: random,
                    fee: value,
                    payout: random,
                    retained: value,
                    input_amount: random,
                    before_deadline: flags & 1 != 0,
                    terminal: flags & 2 != 0,
                    has_payout: flags & 4 != 0,
                    payout_owner: [value, random, value.rotate_left(7), random.rotate_right(11)],
                    input_creation_id: random,
                    input_slot: value as u32,
                    retained_slot: random as u32,
                    payout_slot: (random >> 32) as u32,
                };
                let initial = [value, random];
                let mut expected = initial;
                let expected = interpret(&contract.source.body, &contract, &mut expected, context)
                    .map(|_| expected);
                let actual = native::execute(
                    &contract.opening.program,
                    native::pack_state(initial),
                    context,
                )
                .map(native::unpack_state)
                .map_err(|_| ());
                assert_eq!(actual, expected, "{body}: state {initial:?}, flags {flags}");
                comparisons += 1;
            }
        }
    }
    assert_eq!(comparisons, 185424);
}

#[test]
fn smt_requires_postconditions_and_models_every_abi_instruction() {
    let contract = compile(BUDGET, &parameters()).unwrap();
    let query = verify::smt(&contract).unwrap();
    assert_eq!(query.matches("(check-sat)").count(), 2);
    assert!(query.contains("bvnot fee"));
    assert!(query.contains("old_state0"));
    assert!(query.contains("(declare-fun terminal () Bool)"));
    assert!(verify::smt(&compile(&source("", ""), &parameters()).unwrap()).is_err());
}

#[test]
#[ignore = "requires Z3; set PRUV_TEST_Z3 to its executable"]
fn universal_postconditions_accept_and_reject_real_solver_queries() {
    let path = std::env::var_os("PRUV_TEST_Z3").expect("PRUV_TEST_Z3 must name a Z3 executable");
    let path = Path::new(&path);
    let cases = [
        (BUDGET.to_owned(), Verdict::Verified),
        (INSTRUCTIONS.to_owned(), Verdict::Verified),
        (
            source(
                "remaining += 1;",
                "ensures remaining == old(remaining) + 1;",
            ),
            Verdict::Verified,
        ),
        (
            source(
                "remaining += 2;",
                "ensures remaining == old(remaining) + 1;",
            ),
            Verdict::Counterexample,
        ),
        (
            source("", "ensures remaining <= budget;"),
            Verdict::Counterexample,
        ),
        (
            source("require false;", "ensures true;"),
            Verdict::Infeasible,
        ),
        (
            source(
                "when !terminal { remaining += 1; }",
                "ensures remaining >= old(remaining);",
            ),
            Verdict::Verified,
        ),
        (
            source(
                "remaining = min(remaining, calls);",
                "ensures remaining <= old(remaining);",
            ),
            Verdict::Verified,
        ),
        (
            source(
                "remaining = max(remaining, calls);",
                "ensures remaining >= old(remaining);",
            ),
            Verdict::Verified,
        ),
        (
            source(
                "remaining = 18446744073709551615;",
                "ensures remaining + 1 > 0;",
            ),
            Verdict::Counterexample,
        ),
    ];
    for (text, expected) in cases {
        let contract = compile(&text, &parameters()).unwrap();
        assert_eq!(verify::verify(&contract, path).unwrap(), expected, "{text}");
    }
}

#[test]
#[ignore = "requires Z3; set PRUV_TEST_Z3 to its executable"]
fn native_model_matches_all_opcodes_predicates_and_destinations() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };

    let z3 = std::env::var_os("PRUV_TEST_Z3").expect("PRUV_TEST_Z3");
    let registers = [
        native::Register::State0,
        native::Register::State1,
        native::Register::Scratch0,
        native::Register::Scratch1,
    ];
    let values = [
        [0, 0, 0, 0],
        [1, 2, 1, 0],
        [u64::MAX, 1, u64::MAX, 1],
        [u64::MAX - 1, u64::MAX, 0, u64::MAX],
    ];
    let base = compile(&source("", "ensures true;"), &parameters()).unwrap();
    let mut queries = String::new();
    let mut expected_answers = Vec::new();
    let mut labels = Vec::new();
    for opcode in native::Opcode::ALL {
        for predicate in native::PredicateSource::ALL {
            for inverted in [false, true] {
                for destination in registers {
                    for values in values {
                        let index = labels.len();
                        let left = native::Operand::ALL[index % native::OPERAND_COUNT];
                        let right = native::Operand::ALL[(index * 7 + 1) % native::OPERAND_COUNT];
                        let mut contract = base.clone();
                        let mut program = native::EMPTY_PROGRAM;
                        for (step, (register, value)) in
                            [native::Register::Scratch0, native::Register::Scratch1]
                                .into_iter()
                                .zip([values[2], values[3]])
                                .enumerate()
                        {
                            program[step] = native::Instruction::new(
                                native::Opcode::Move,
                                register,
                                native::Operand::Immediate,
                                native::Operand::Zero,
                                value,
                            )
                            .to_fields();
                        }
                        program[2] =
                            native::Instruction::new(opcode, destination, left, right, values[1])
                                .when(native::Predicate {
                                    source: predicate,
                                    inverted,
                                })
                                .to_fields();
                        if destination == native::Register::Scratch0 {
                            program[3] = native::Instruction::new(
                                native::Opcode::Move,
                                native::Register::State0,
                                native::Operand::Scratch0,
                                native::Operand::Zero,
                                0,
                            )
                            .to_fields();
                        } else if destination == native::Register::Scratch1 {
                            program[3] = native::Instruction::new(
                                native::Opcode::Move,
                                native::Register::State1,
                                native::Operand::Scratch1,
                                native::Operand::Zero,
                                0,
                            )
                            .to_fields();
                        }
                        contract.opening.program = program;
                        let height = [999, 1000, 0, u64::MAX][index % 4];
                        let context = native::Context {
                            height,
                            fee: values[1],
                            payout: values[2],
                            retained: values[3],
                            input_amount: values[0],
                            before_deadline: height < contract.opening.deadline,
                            terminal: index & 1 != 0,
                            has_payout: index & 2 != 0,
                            payout_owner: values,
                            input_creation_id: values[0],
                            input_slot: values[1] as u32,
                            retained_slot: values[2] as u32,
                            payout_slot: values[3] as u32,
                        };
                        let native_result = native::execute(
                            &program,
                            native::pack_state([values[0], values[1]]),
                            context,
                        );
                        let result = native_result.map(native::unpack_state).unwrap_or([0, 0]);
                        contract.source.ensures = crate::syntax::parse(&source(
                            "",
                            &format!(
                                "ensures remaining == {}; ensures calls == {};",
                                result[0], result[1]
                            ),
                        ))
                        .unwrap()
                        .ensures;
                        let query = verify::smt(&contract).unwrap();
                        let split = query.find("; Feasibility").unwrap();
                        queries.push_str("(reset)\n");
                        queries.push_str(&query[..split]);
                        for (name, value) in [
                            ("old_state0", values[0]),
                            ("old_state1", values[1]),
                            ("height", height),
                            ("fee", context.fee),
                            ("payout", context.payout),
                            ("retained", context.retained),
                            ("input_amount", context.input_amount),
                            ("payout_owner0", values[0]),
                            ("payout_owner1", values[1]),
                            ("payout_owner2", values[2]),
                            ("payout_owner3", values[3]),
                            ("input_creation_id", context.input_creation_id),
                            ("input_slot", context.input_slot.into()),
                            ("retained_slot", context.retained_slot.into()),
                            ("payout_slot", context.payout_slot.into()),
                        ] {
                            queries.push_str(&format!("(assert (= {name} (_ bv{value} 64)))\n"));
                        }
                        queries.push_str(&format!(
                            "(assert (= terminal {}))\n(assert (= has_payout {}))\n",
                            context.terminal, context.has_payout
                        ));
                        queries.push_str(&query[split..]);
                        expected_answers.extend([
                            if native_result.is_ok() {
                                "sat"
                            } else {
                                "unsat"
                            },
                            "unsat",
                        ]);
                        labels.push(format!("{opcode:?}, {predicate:?}, inverted={inverted}, {destination:?}, {values:?}, {left:?}, {right:?}"));
                    }
                }
            }
        }
    }
    assert_eq!(labels.len(), 1920);
    let mut child = Command::new(z3)
        .args(["-in", "-smt2", "-T:60"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || stdin.write_all(queries.as_bytes()));
    let output = child.wait_with_output().unwrap();
    writer.join().unwrap().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let actual: Vec<_> = stdout.split_whitespace().collect();
    assert_eq!(actual.len(), expected_answers.len(), "{stdout}");
    for (index, (actual, expected)) in actual.into_iter().zip(expected_answers).enumerate() {
        assert_eq!(actual, expected, "{}", labels[index / 2]);
    }
}

#[test]
fn compile_does_not_depend_on_parameter_object_order() {
    let ordered: BTreeMap<String, serde_json::Value> =
        serde_json::from_value(parameters()).unwrap();
    let reordered: serde_json::Value = serde_json::from_str(&format!(
        "{{{}}}",
        ordered
            .iter()
            .rev()
            .map(|(key, value)| format!("\"{key}\":{value}"))
            .collect::<Vec<_>>()
            .join(",")
    ))
    .unwrap();
    assert_eq!(
        compile(BUDGET, &parameters()).unwrap().definition(),
        compile(BUDGET, &reordered).unwrap().definition()
    );
}

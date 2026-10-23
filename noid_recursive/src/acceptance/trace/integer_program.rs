// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Fixed-shape twin of the v2 bounded integer interpreter.
//! The enclosing object relation supplies authenticated context wires and
//! committed program/current/next state wires. No context is accepted from a
//! standalone caller assertion. All instructions and checks remain present
//! for every reserved contract position, including inactive positions.

use noid_tx::experimental_object::integer_program::{
    INSTRUCTION_BITS, OPCODE_COUNT, OPERAND_COUNT, PREDICATE_COUNT, PROGRAM_STEPS,
};

use super::{flat_const, mul, pin_zero, range_check_bits, FieldR1csBuilder, LinExpr, Wire, F128};

pub struct ContextTrace {
    pub height: LinExpr,
    pub fee: LinExpr,
    pub payout: LinExpr,
    pub retained: LinExpr,
    pub input_amount: LinExpr,
    pub before_deadline: LinExpr,
    pub terminal: LinExpr,
    pub has_payout: LinExpr,
    pub payout_owner: [LinExpr; 4],
    pub input_creation_id: LinExpr,
    pub input_slot: LinExpr,
    pub retained_slot: LinExpr,
    pub payout_slot: LinExpr,
}

impl ContextTrace {
    fn bind_ranges(&self, b: &mut FieldR1csBuilder) {
        for value in [
            &self.height,
            &self.fee,
            &self.payout,
            &self.retained,
            &self.input_amount,
            &self.input_creation_id,
        ]
        .into_iter()
        .chain(&self.payout_owner)
        {
            range_check_bits(b, value, 64);
        }
        for value in [&self.input_slot, &self.retained_slot, &self.payout_slot] {
            range_check_bits(b, value, 32);
        }
        for value in [&self.before_deadline, &self.terminal, &self.has_payout] {
            boolean(b, value);
        }
    }

    fn operands(&self, registers: &[LinExpr; 4], immediate: &LinExpr) -> [LinExpr; OPERAND_COUNT] {
        [
            registers[0].clone(),
            registers[1].clone(),
            registers[2].clone(),
            registers[3].clone(),
            immediate.clone(),
            self.height.clone(),
            self.fee.clone(),
            self.payout.clone(),
            self.retained.clone(),
            self.input_amount.clone(),
            self.before_deadline.clone(),
            self.terminal.clone(),
            self.has_payout.clone(),
            LinExpr::zero(),
            LinExpr::constant(F128::ONE),
            self.before_deadline.add_const(F128::ONE),
            self.payout_owner[0].clone(),
            self.payout_owner[1].clone(),
            self.payout_owner[2].clone(),
            self.payout_owner[3].clone(),
            self.input_creation_id.clone(),
            self.input_slot.clone(),
            self.retained_slot.clone(),
            self.payout_slot.clone(),
        ]
    }

    fn predicates(&self, registers: &[LinExpr; 4]) -> [LinExpr; PREDICATE_COUNT] {
        [
            LinExpr::constant(F128::ONE),
            self.before_deadline.clone(),
            self.terminal.clone(),
            self.has_payout.clone(),
            registers[2].clone(),
            registers[3].clone(),
        ]
    }
}

fn boolean(b: &mut FieldR1csBuilder, value: &LinExpr) {
    let invalid = mul(b, value, &value.add_const(F128::ONE));
    pin_zero(b, &invalid);
}

/// Binary selector tensor, ordered by the little-endian instruction bits.
fn selectors(b: &mut FieldR1csBuilder, bits: &[Wire], allowed: usize) -> Vec<LinExpr> {
    let mut values = vec![LinExpr::constant(F128::ONE)];
    for &wire in bits {
        let bit = LinExpr::from_wire(wire);
        let len = values.len();
        let mut next = vec![LinExpr::zero(); len * 2];
        for (index, value) in values.into_iter().enumerate() {
            let one = mul(b, &value, &bit);
            next[index] = value.add(&one);
            next[index + len] = one;
        }
        values = next;
    }
    assert!(allowed <= values.len());
    let invalid = values[allowed..]
        .iter()
        .fold(LinExpr::zero(), |sum, value| sum.add(value));
    pin_zero(b, &invalid);
    values.truncate(allowed);
    values
}

fn select(b: &mut FieldR1csBuilder, selectors: &[LinExpr], values: &[LinExpr]) -> LinExpr {
    assert_eq!(selectors.len(), values.len());
    selectors
        .iter()
        .zip(values)
        .fold(LinExpr::zero(), |sum, (selector, value)| {
            sum.add(&mul(b, selector, value))
        })
}

fn pack_bits(bits: &[Wire], shift: usize) -> LinExpr {
    assert!(bits.len() + shift <= 128);
    bits.iter()
        .enumerate()
        .fold(LinExpr::zero(), |sum, (index, &wire)| {
            sum.add(&LinExpr::from_wire(wire).scale(flat_const(1u128 << (shift + index))))
        })
}

/// Reuse the operand bits for exact unsigned comparison and integer add/sub.
/// Subtraction is a + (~b) + 1; a final carry of one means no underflow.
/// Addition requires final carry zero. The caller gates that final check on
/// the instruction and predicate, so an unexecuted arithmetic branch cannot
/// block recovery or constrain unrelated instructions.
fn integer_results(
    b: &mut FieldR1csBuilder,
    left: &[Wire],
    right: &[Wire],
    subtract: &LinExpr,
) -> (LinExpr, LinExpr, LinExpr, LinExpr) {
    assert_eq!(left.len(), 64);
    assert_eq!(right.len(), 64);
    let mut less = LinExpr::zero();
    let mut equal = LinExpr::constant(F128::ONE);
    let mut carry = subtract.clone();
    let mut sum = LinExpr::zero();
    for (index, (&a, &c)) in left.iter().zip(right).enumerate() {
        let a = LinExpr::from_wire(a);
        let c = LinExpr::from_wire(c);
        let matching = a.add(&c).add_const(F128::ONE);
        let less_here = mul(b, &a.add_const(F128::ONE), &c);
        less = less_here.add(&mul(b, &less, &matching));
        equal = mul(b, &equal, &matching);

        let adjusted = c.add(subtract);
        let sum_bit = a.add(&adjusted).add(&carry);
        sum = sum.add(&sum_bit.scale(flat_const(1u128 << index)));
        let direct_carry = mul(b, &a, &adjusted);
        carry = direct_carry.add(&mul(b, &carry, &a.add(&adjusted)));
    }
    (less, equal, sum, carry)
}

/// Compact unsigned arithmetic for the v2.1 relation.
fn integer_results_v2_1(
    b: &mut FieldR1csBuilder,
    left: &[Wire],
    right: &[Wire],
    subtract: &LinExpr,
) -> (LinExpr, LinExpr, LinExpr, LinExpr) {
    assert_eq!(left.len(), 64);
    assert_eq!(right.len(), 64);
    let difference = pack_bits(left, 0).add(&pack_bits(right, 0));
    let value = difference.eval(b.values());
    let equal = LinExpr::from_wire(b.alloc_f128(if value == F128::ZERO {
        F128::ONE
    } else {
        F128::ZERO
    }));
    let inverse = LinExpr::from_wire(b.alloc_f128(if value == F128::ZERO {
        F128::ZERO
    } else {
        value.inv()
    }));
    let inverse_check = mul(b, &difference, &inverse).add(&equal);
    super::pin_eq(b, &inverse_check, &LinExpr::constant(F128::ONE));
    let zero_check = mul(b, &difference, &equal);
    pin_zero(b, &zero_check);

    let mut less = LinExpr::zero();
    let mut carry = subtract.clone();
    let mut sum = LinExpr::zero();
    for (index, (&a, &c)) in left.iter().zip(right).enumerate() {
        let a = LinExpr::from_wire(a);
        let c = LinExpr::from_wire(c);
        let comparison = mul(b, &a.add(&c).add_const(F128::ONE), &less.add(&c));
        less = comparison.add(&c);

        let adjusted = c.add(subtract);
        let sum_bit = a.add(&adjusted).add(&carry);
        sum = sum.add(&sum_bit.scale(flat_const(1u128 << index)));
        // For bits x, y, z, the carry is (x + z)(y + z) + z.
        // Keep z sparse so the next row also has bounded support.
        let next_carry = mul(b, &adjusted.add(&a), &carry.add(&a));
        carry = next_carry.add(&a);
    }
    (less, equal, sum, carry)
}

pub fn bind_program(
    b: &mut FieldR1csBuilder,
    program: &[[LinExpr; 2]; PROGRAM_STEPS],
    current: &LinExpr,
    next: &LinExpr,
    context: &ContextTrace,
    live: &LinExpr,
) {
    bind_program_with_arithmetic(b, program, current, next, context, live, false);
}

pub fn bind_program_v2_1(
    b: &mut FieldR1csBuilder,
    program: &[[LinExpr; 2]; PROGRAM_STEPS],
    current: &LinExpr,
    next: &LinExpr,
    context: &ContextTrace,
    live: &LinExpr,
) {
    bind_program_with_arithmetic(b, program, current, next, context, live, true);
}

fn bind_program_with_arithmetic(
    b: &mut FieldR1csBuilder,
    program: &[[LinExpr; 2]; PROGRAM_STEPS],
    current: &LinExpr,
    next: &LinExpr,
    context: &ContextTrace,
    live: &LinExpr,
    compact_arithmetic: bool,
) {
    boolean(b, live);
    context.bind_ranges(b);
    let current_bits = range_check_bits(b, current, 128);
    let mut registers = [
        pack_bits(&current_bits[..64], 0),
        pack_bits(&current_bits[64..], 0),
        LinExpr::zero(),
        LinExpr::zero(),
    ];

    for [descriptor, immediate] in program {
        let bits = range_check_bits(b, descriptor, INSTRUCTION_BITS);
        range_check_bits(b, immediate, 64);
        let op = selectors(b, &bits[..4], OPCODE_COUNT);
        let destination = selectors(b, &bits[4..6], 4);
        let left_selector = selectors(b, &bits[6..11], OPERAND_COUNT);
        let right_selector = selectors(b, &bits[11..16], OPERAND_COUNT);
        let predicate_selector = selectors(b, &bits[16..19], PREDICATE_COUNT);
        let predicate = select(b, &predicate_selector, &context.predicates(&registers));
        boolean(b, &predicate);
        let predicate = predicate.add(&LinExpr::from_wire(bits[19]));
        let enabled = mul(b, live, &predicate);
        let operands = context.operands(&registers, immediate);
        let left = select(b, &left_selector, &operands);
        let right = select(b, &right_selector, &operands);
        let old_destination = select(b, &destination, &registers);
        let left_bits = range_check_bits(b, &left, 64);
        let right_bits = range_check_bits(b, &right, 64);
        let (less, equal, sum, carry) = if compact_arithmetic {
            integer_results_v2_1(b, &left_bits, &right_bits, &op[3])
        } else {
            integer_results(b, &left_bits, &right_bits, &op[3])
        };

        let arithmetic = mul(b, &enabled, &op[2].add(&op[3]));
        let bad_carry = mul(b, &arithmetic, &carry.add(&op[3]));
        pin_zero(b, &bad_carry);
        let assert_equal = mul(b, &enabled, &op[8]);
        let unequal = mul(b, &assert_equal, &left.add(&right));
        pin_zero(b, &unequal);
        let assert_le = mul(b, &enabled, &op[9]);
        let greater = less.add(&equal).add_const(F128::ONE);
        let bad_order = mul(b, &assert_le, &greater);
        pin_zero(b, &bad_order);

        let minimum = right.add(&mul(b, &less, &left.add(&right)));
        let maximum = left.add(&right).add(&minimum);
        let keep = op[0].add(&op[8]).add(&op[9]);
        let result = mul(b, &keep, &old_destination)
            .add(&mul(b, &op[1], &left))
            .add(&mul(b, &op[2].add(&op[3]), &sum))
            .add(&mul(b, &op[4], &minimum))
            .add(&mul(b, &op[5], &maximum))
            .add(&mul(b, &op[6], &less))
            .add(&mul(b, &op[7], &equal));
        registers = std::array::from_fn(|index| {
            let writes = mul(b, &enabled, &destination[index]);
            registers[index].add(&mul(b, &writes, &result.add(&registers[index])))
        });
    }

    let low = range_check_bits(b, &registers[0], 64);
    let high = range_check_bits(b, &registers[1], 64);
    let packed = pack_bits(&low, 0).add(&pack_bits(&high, 64));
    let mismatch = mul(b, live, &packed.add(next));
    pin_zero(b, &mismatch);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acceptance::trace::alloc_block;
    use noid_core::Block128;
    use noid_tx::experimental_object::integer_program::{self as native, *};

    fn run(
        program: &Program,
        current: Block128,
        next: Block128,
        context: Context,
    ) -> (bool, [u8; 32], usize) {
        let mut b = FieldR1csBuilder::new();
        let mut field = |value| alloc_block(&mut b, Block128(value));
        let program = program.map(|pair| pair.map(|value| field(value.0)));
        let current = field(current.0);
        let next = field(next.0);
        let context = ContextTrace {
            height: field(context.height as u128),
            fee: field(context.fee as u128),
            payout: field(context.payout as u128),
            retained: field(context.retained as u128),
            input_amount: field(context.input_amount as u128),
            before_deadline: field(context.before_deadline as u128),
            terminal: field(context.terminal as u128),
            has_payout: field(context.has_payout as u128),
            payout_owner: context.payout_owner.map(|value| field(value as u128)),
            input_creation_id: field(context.input_creation_id as u128),
            input_slot: field(context.input_slot as u128),
            retained_slot: field(context.retained_slot as u128),
            payout_slot: field(context.payout_slot as u128),
        };
        bind_program(
            &mut b,
            &program,
            &current,
            &next,
            &context,
            &LinExpr::constant(F128::ONE),
        );
        let rows = b.num_wires();
        let (matrix, witness) = b.build();
        (
            matrix.satisfies(&witness),
            matrix.structural_statement_digest(),
            rows,
        )
    }

    #[test]
    fn every_predicate_and_its_inverse_select_exactly_one_update() {
        let mut digest = None;
        for source in PredicateSource::ALL {
            for inverted in [false, true] {
                for bit in [0u64, 1] {
                    let mut program = EMPTY_PROGRAM;
                    program[0] = Instruction::new(
                        Opcode::Move,
                        Register::Scratch0,
                        Operand::Immediate,
                        Operand::Zero,
                        bit,
                    )
                    .to_fields();
                    program[1] = Instruction::new(
                        Opcode::Move,
                        Register::Scratch1,
                        Operand::Immediate,
                        Operand::Zero,
                        bit ^ 1,
                    )
                    .to_fields();
                    program[2] = Instruction::new(
                        Opcode::Move,
                        Register::State0,
                        Operand::Immediate,
                        Operand::Zero,
                        77,
                    )
                    .when(Predicate { source, inverted })
                    .to_fields();
                    let context = Context {
                        before_deadline: bit == 1,
                        terminal: bit == 0,
                        has_payout: bit == 1,
                        ..Context::default()
                    };
                    let predicate = match source {
                        PredicateSource::Always => true,
                        PredicateSource::BeforeDeadline
                        | PredicateSource::HasPayout
                        | PredicateSource::Scratch0 => bit == 1,
                        PredicateSource::Terminal | PredicateSource::Scratch1 => bit == 0,
                    };
                    let current = pack_state([11, u64::MAX]);
                    let expected =
                        pack_state([if predicate != inverted { 77 } else { 11 }, u64::MAX]);
                    assert_eq!(native::execute(&program, current, context), Ok(expected));
                    let (valid, shape, _) = run(&program, current, expected, context);
                    assert!(valid, "{source:?}, inverted={inverted}, bit={bit}");
                    assert!(digest.is_none_or(|previous| previous == shape));
                    digest = Some(shape);
                }
            }
        }
    }

    #[test]
    fn all_operations_and_integer_boundaries_match_native_with_one_matrix() {
        let mut digest = None;
        for opcode in Opcode::ALL {
            for (left, right) in [
                (0, 0),
                (0, 1),
                (1, 0),
                (1, 1),
                (u64::MAX, 1),
                (u64::MAX, u64::MAX),
                (1 << 63, 1 << 63),
                ((1 << 63) - 1, 1),
            ] {
                let mut program = EMPTY_PROGRAM;
                program[0] = Instruction::new(
                    opcode,
                    Register::State0,
                    Operand::State0,
                    Operand::Immediate,
                    right,
                )
                .to_fields();
                let current = pack_state([left, 77]);
                let expected = native::execute(&program, current, Context::default());
                let (valid, actual_digest, rows) = run(
                    &program,
                    current,
                    expected.unwrap_or(current),
                    Context::default(),
                );
                assert_eq!(valid, expected.is_ok(), "{opcode:?}({left}, {right})");
                if digest.is_none() {
                    eprintln!("integer program component: {rows} wires for {PROGRAM_STEPS} instructions; full object relation not included");
                }
                assert!(digest.is_none_or(|value| value == actual_digest));
                digest = Some(actual_digest);
                if let Ok(next) = expected {
                    assert!(!run(&program, current, Block128(next.0 ^ 1), Context::default()).0);
                }
            }
        }
    }

    #[test]
    fn malformed_code_and_non_boolean_predicates_reject_in_the_trace() {
        for word in [10, 24 << 6, 24 << 11, 6 << 16, 1 << INSTRUCTION_BITS] {
            let mut program = EMPTY_PROGRAM;
            program[0][0] = Block128(word);
            assert!(!run(&program, Block128(0), Block128(0), Context::default()).0);
        }
        let mut program = EMPTY_PROGRAM;
        program[0][1] = Block128(1u128 << 64);
        assert!(!run(&program, Block128(0), Block128(0), Context::default()).0);
        program = EMPTY_PROGRAM;
        program[0] = Instruction::new(
            Opcode::Move,
            Register::Scratch0,
            Operand::Immediate,
            Operand::Zero,
            2,
        )
        .to_fields();
        program[1] = Instruction::new(
            Opcode::Move,
            Register::State0,
            Operand::One,
            Operand::Zero,
            0,
        )
        .when(Predicate {
            source: PredicateSource::Scratch0,
            inverted: false,
        })
        .to_fields();
        assert!(!run(&program, Block128(0), Block128(1), Context::default()).0);
    }

    #[test]
    fn height_guards_and_skipped_overflow_match_recovery_semantics() {
        let mut program = EMPTY_PROGRAM;
        program[0] = Instruction::new(
            Opcode::Add,
            Register::State0,
            Operand::Height,
            Operand::Immediate,
            30,
        )
        .when(Predicate::BEFORE_DEADLINE)
        .to_fields();
        let current = pack_state([7, 9]);
        for (height, before_deadline) in [
            (0, true),
            (210_537, true),
            (u64::MAX, false),
            (u64::MAX, true),
        ] {
            let context = Context {
                height,
                before_deadline,
                ..Context::default()
            };
            let expected = native::execute(&program, current, context);
            let (valid, _, _) = run(&program, current, expected.unwrap_or(current), context);
            assert_eq!(valid, expected.is_ok());
        }
        let context = Context {
            height: 900,
            before_deadline: true,
            ..Context::default()
        };
        let next = native::execute(&program, current, context).unwrap();
        assert!(
            !run(
                &program,
                current,
                next,
                Context {
                    height: 901,
                    ..context
                }
            )
            .0
        );
        assert!(
            !run(
                &program,
                current,
                next,
                Context {
                    before_deadline: false,
                    ..context
                }
            )
            .0
        );
    }

    #[test]
    fn every_operand_is_bound_to_its_selected_context_or_register() {
        let context = Context {
            height: 90,
            fee: 3,
            payout: 47,
            retained: 51,
            input_amount: 101,
            before_deadline: true,
            terminal: false,
            has_payout: true,
            payout_owner: [11, 22, 33, 44],
            input_creation_id: 12345,
            input_slot: 300,
            retained_slot: 301,
            payout_slot: 302,
        };
        for source in Operand::ALL {
            let mut program = EMPTY_PROGRAM;
            program[0] = Instruction::new(
                Opcode::Move,
                Register::Scratch0,
                Operand::Immediate,
                Operand::Zero,
                21,
            )
            .to_fields();
            program[1] = Instruction::new(
                Opcode::Move,
                Register::Scratch1,
                Operand::Immediate,
                Operand::Zero,
                31,
            )
            .to_fields();
            program[2] =
                Instruction::new(Opcode::Move, Register::State0, source, Operand::Zero, 41)
                    .to_fields();
            let current = pack_state([17, 27]);
            let next = native::execute(&program, current, context).unwrap();
            assert!(run(&program, current, next, context).0, "source={source:?}");
            assert!(!run(&program, current, Block128(next.0 ^ 1), context).0);
        }
    }
}

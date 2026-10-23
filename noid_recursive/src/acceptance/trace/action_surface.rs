// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Hash-bound transaction selectors shared by the C' semantic relation.
//!
//! The final Tx8x2 spine exposes all 16 raw body-hash leaves as statement
//! wires. This module makes the flags leaf the only in-trace liveness source,
//! enforces the canonical zero form of dead entries, and exposes PagedSpend
//! START/END delimiters. The group scanner later binds the common input owner
//! to the one logical authorization. Ordered actions and the exact-state
//! overlay build on these wires in the next C' slice.

use super::tx_body_spine::SpineInputsTrace;
use super::{
    const_block, mul, pin_eq, pin_zero, range_check_bits, FieldR1csBuilder, LinExpr, Wire, F128,
};
use noid_core::{Block128, TowerField};
pub use noid_tx::body_hash::{
    TX8X2_LEAF_EPOCH_ANCHOR as LEAF_EPOCH_ANCHOR, TX8X2_LEAF_FEE as LEAF_FEE,
    TX8X2_LEAF_FLAGS as LEAF_FLAGS, TX8X2_LEAF_INPUT_BASE as LEAF_INPUT_BASE,
    TX8X2_LEAF_INPUT_OWNER as LEAF_INPUT_OWNER, TX8X2_LEAF_OUTPUT0_DATA as LEAF_OUTPUT0_DATA,
    TX8X2_LEAF_OUTPUT0_OWNER as LEAF_OUTPUT0_OWNER, TX8X2_LEAF_OUTPUT1_DATA as LEAF_OUTPUT1_DATA,
    TX8X2_LEAF_OUTPUT1_OWNER as LEAF_OUTPUT1_OWNER,
};

pub const INPUT_SELECTORS: usize = noid_tx::TX_INPUTS;
pub const OUTPUT_SELECTORS: usize = noid_tx::TX_OUTPUTS;
pub const ACTION_VALIDITY_BITS: usize = INPUT_SELECTORS + OUTPUT_SELECTORS;
pub const PAGE_VALIDITY_BITS: usize = ACTION_VALIDITY_BITS + 4;

const _: () = assert!(LEAF_INPUT_BASE + INPUT_SELECTORS == LEAF_OUTPUT0_DATA);
const _: () = assert!(LEAF_OUTPUT1_OWNER + 1 == LEAF_FLAGS);
const _: () = assert!(LEAF_FLAGS + 1 == super::tx_body_spine::TX_BODY_RAW_LEAVES);

/// One body-order action candidate. Every semantic lane is selected by
/// `live`, so a dead row is the unique all-zero action row.
#[derive(Clone)]
pub struct ActionRowTrace {
    pub live: LinExpr,
    pub slot_index: LinExpr,
    /// Before the allocator pass: Spend is packed `(amount, creation_id)` and
    /// Mint is the proven-u64 output amount. The allocator injects each mint's
    /// body-order creation id into the high half before slot sorting, after
    /// which this is the exact packed state value for both roles.
    pub value: LinExpr,
    pub owner: [LinExpr; 2],
    /// Zero for Spend, one for Mint, and zero for a dead row.
    pub is_mint: LinExpr,
}

/// Mandatory coinbase action together with the source amount's one and only
/// production u64 decomposition.  The fee/reward relation consumes these
/// exact bits instead of range-checking the coinbase amount a second time.
pub struct CoinbaseActionTrace {
    pub action: ActionRowTrace,
    pub amount: LinExpr,
    pub amount_bits: [Wire; 64],
}

/// Optional two-output system payout selected by the deterministic height
/// schedule. The physical spine slot is always present in the fixed circuit:
/// it is the complete canonical ghost body when `live == 0`.
pub struct DevelopmentPayoutActionTrace {
    pub actions: [ActionRowTrace; 2],
    pub amount_each: LinExpr,
}

/// Selector surface of one Tx8x2 user body.
///
/// `raw_*` are committed by `L15`; `selected_* = tx_live * raw_*`
/// additionally gate tier-padding ghost transactions out of block resource
/// totals without changing their canonical ghost body or authorization proof.
pub struct ActionSurfaceTrace {
    /// The exact outer transaction-liveness expression whose product defines
    /// every `selected_*` selector.  Downstream arithmetic consumes this field
    /// directly so fee/totals cannot accidentally use a different witness.
    pub tx_live: LinExpr,
    pub raw_inputs: [LinExpr; INPUT_SELECTORS],
    pub raw_outputs: [LinExpr; OUTPUT_SELECTORS],
    /// PagedSpend group delimiters committed in validity bits 10 and 11.
    /// They never become state actions; the block scanner consumes them.
    pub start: LinExpr,
    pub end: LinExpr,
    /// Research-v2 object-contract and terminal-transition selectors. Both
    /// are committed by the existing body hash. They never become State
    /// actions; the heterogeneous HistoryStep binds them to the contract
    /// Meta-A opening and authorization partition.
    pub contract: LinExpr,
    pub terminal: LinExpr,
    /// Native data/header bits, or zero in all earlier relation profiles.
    pub native: LinExpr,
    pub native_header: LinExpr,
    pub selected_inputs: [LinExpr; INPUT_SELECTORS],
    pub selected_outputs: [LinExpr; OUTPUT_SELECTORS],
    pub input_rows: [ActionRowTrace; INPUT_SELECTORS],
    pub output_rows: [ActionRowTrace; OUTPUT_SELECTORS],
}

impl ActionSurfaceTrace {
    /// Canonical body order: every physical input position, then both output
    /// positions. Stable block-wide compaction removes the dead rows later.
    pub fn ordered_rows(&self) -> impl Iterator<Item = ActionRowTrace> + '_ {
        self.input_rows
            .iter()
            .chain(self.output_rows.iter())
            .cloned()
    }
}

fn bind_dead_pair(b: &mut FieldR1csBuilder, live: &LinExpr, pair: &[LinExpr; 2]) {
    // Characteristic two: 1 + live is the boolean NOT of live.
    let dead = live.add_const(F128::ONE);
    for lane in pair {
        let dead_lane = mul(b, &dead, lane);
        pin_zero(b, &dead_lane);
    }
}

fn selected_row(
    b: &mut FieldR1csBuilder,
    live: &LinExpr,
    data: &[LinExpr; 2],
    owner: &[LinExpr; 2],
    is_mint: bool,
) -> ActionRowTrace {
    ActionRowTrace {
        live: live.clone(),
        slot_index: mul(b, live, &data[0]),
        value: mul(b, live, &data[1]),
        owner: std::array::from_fn(|lane| mul(b, live, &owner[lane])),
        is_mint: if is_mint {
            live.clone()
        } else {
            LinExpr::zero()
        },
    }
}

/// Bind one physical page's validity bitmap and canonical dead entries to
/// already allocated spine statement wires. Owner continuity and the one
/// logical authorization are group-level PagedSpend obligations. Coinbase has
/// a separate surface.
pub fn bind_user_action_surface(
    b: &mut FieldR1csBuilder,
    spine: &SpineInputsTrace,
    tx_live: &LinExpr,
) -> ActionSurfaceTrace {
    bind_user_action_surface_for_profile(b, spine, tx_live, true)
}

/// The legacy relation must retain its original twelve-bit page bitmap and
/// exact row order. This is a matrix-build choice, never a witness selector.
pub(crate) fn bind_user_action_surface_for_profile(
    b: &mut FieldR1csBuilder,
    spine: &SpineInputsTrace,
    tx_live: &LinExpr,
    contracts: bool,
) -> ActionSurfaceTrace {
    bind_user_action_surface_inner(b, spine, tx_live, contracts, false)
}

pub fn bind_user_action_surface_v2_1(
    b: &mut FieldR1csBuilder,
    spine: &SpineInputsTrace,
    tx_live: &LinExpr,
) -> ActionSurfaceTrace {
    bind_user_action_surface_inner(b, spine, tx_live, true, true)
}

fn bind_user_action_surface_inner(
    b: &mut FieldR1csBuilder,
    spine: &SpineInputsTrace,
    tx_live: &LinExpr,
    contracts: bool,
    native_pages: bool,
) -> ActionSurfaceTrace {
    // Capacity builds already constrain their shared liveness wires. Keeping
    // this local booleanity also makes the component sound in isolation.
    let tx_live_sq = mul(b, tx_live, tx_live);
    pin_eq(b, &tx_live_sq, tx_live);

    // L15 = [validity_bitmap, is_coinbase]. A physical user page has ten
    // action bits followed by START, END, CONTRACT and TERMINAL.
    let width = ACTION_VALIDITY_BITS
        + if native_pages {
            6
        } else if contracts {
            4
        } else {
            2
        };
    let bits = range_check_bits(b, &spine.leaves[LEAF_FLAGS][0], width);
    pin_zero(b, &spine.leaves[LEAF_FLAGS][1]);
    let raw: Vec<LinExpr> = bits.into_iter().map(LinExpr::from_wire).collect();
    let raw_inputs: [LinExpr; INPUT_SELECTORS] = std::array::from_fn(|i| raw[i].clone());
    let raw_outputs: [LinExpr; OUTPUT_SELECTORS] =
        std::array::from_fn(|i| raw[INPUT_SELECTORS + i].clone());
    let start = raw[ACTION_VALIDITY_BITS].clone();
    let end = raw[ACTION_VALIDITY_BITS + 1].clone();
    let (contract, terminal) = if contracts {
        let contract = raw[ACTION_VALIDITY_BITS + 2].clone();
        let terminal = raw[ACTION_VALIDITY_BITS + 3].clone();
        let terminal_without_contract = mul(b, &terminal, &contract.add_const(F128::ONE));
        pin_zero(b, &terminal_without_contract);
        (contract, terminal)
    } else {
        (LinExpr::zero(), LinExpr::zero())
    };
    let (native, native_header) = if native_pages {
        let native = raw[14].clone();
        let header = raw[15].clone();
        let header_without_native = mul(b, &header, &native.add_const(F128::ONE));
        pin_zero(b, &header_without_native);
        let mixed_contract = mul(b, &native, &contract);
        pin_zero(b, &mixed_contract);
        let header_without_start = mul(b, &header, &start.add_const(F128::ONE));
        pin_zero(b, &header_without_start);
        let header_end = mul(b, &header, &end);
        pin_zero(b, &header_end);
        let data_start = mul(b, &native.add(&header), &start);
        pin_zero(b, &data_start);
        for bit in raw_inputs.iter().chain(&raw_outputs) {
            let header_action = mul(b, &header, bit);
            pin_zero(b, &header_action);
        }
        (native, header)
    } else {
        (LinExpr::zero(), LinExpr::zero())
    };
    for (index, live) in raw_inputs.iter().enumerate() {
        let retained = if native_pages {
            live.add(&native_header)
        } else {
            live.clone()
        };
        bind_dead_pair(b, &retained, &spine.leaves[LEAF_INPUT_BASE + index]);
    }
    for (index, live) in raw_outputs.iter().enumerate() {
        let data_leaf = LEAF_OUTPUT0_DATA + 2 * index;
        let retained = if native_pages {
            live.add(&native_header)
        } else {
            live.clone()
        };
        bind_dead_pair(b, &retained, &spine.leaves[data_leaf]);
        bind_dead_pair(b, &retained, &spine.leaves[data_leaf + 1]);
    }

    let selected_inputs = std::array::from_fn(|i| mul(b, tx_live, &raw_inputs[i]));
    let selected_outputs = std::array::from_fn(|i| mul(b, tx_live, &raw_outputs[i]));
    let input_rows = std::array::from_fn(|i| {
        selected_row(
            b,
            &selected_inputs[i],
            &spine.leaves[LEAF_INPUT_BASE + i],
            &spine.leaves[LEAF_INPUT_OWNER],
            false,
        )
    });
    let output_rows = std::array::from_fn(|i| {
        let data_leaf = LEAF_OUTPUT0_DATA + 2 * i;
        selected_row(
            b,
            &selected_outputs[i],
            &spine.leaves[data_leaf],
            &spine.leaves[data_leaf + 1],
            true,
        )
    });

    ActionSurfaceTrace {
        tx_live: tx_live.clone(),
        raw_inputs,
        raw_outputs,
        start,
        end,
        contract,
        terminal,
        native,
        native_header,
        selected_inputs,
        selected_outputs,
        input_rows,
        output_rows,
    }
}

/// Bind the mandatory non-genesis coinbase shape and return its sole action.
/// Coinbase contributes exactly output zero; there are no physical dead
/// candidates to compact because every other position is fixed to zero here.
pub fn bind_coinbase_action_with_amount(
    b: &mut FieldR1csBuilder,
    spine: &SpineInputsTrace,
) -> CoinbaseActionTrace {
    let bits = range_check_bits(b, &spine.leaves[LEAF_FLAGS][0], ACTION_VALIDITY_BITS);
    let bits: [LinExpr; ACTION_VALIDITY_BITS] =
        std::array::from_fn(|i| LinExpr::from_wire(bits[i]));
    for input in &bits[..INPUT_SELECTORS] {
        pin_zero(b, input);
    }
    pin_eq(
        b,
        &bits[INPUT_SELECTORS],
        &const_block(Block128::from(1u128)),
    );
    pin_zero(b, &bits[INPUT_SELECTORS + 1]);
    pin_eq(
        b,
        &spine.leaves[LEAF_FLAGS][1],
        &const_block(Block128::from(1u128)),
    );
    for lane in &spine.leaves[LEAF_FEE] {
        pin_zero(b, lane);
    }
    for lane in &spine.leaves[LEAF_INPUT_OWNER] {
        pin_zero(b, lane);
    }
    for input in 0..INPUT_SELECTORS {
        bind_dead_pair(b, &bits[input], &spine.leaves[LEAF_INPUT_BASE + input]);
    }
    bind_dead_pair(
        b,
        &bits[INPUT_SELECTORS + 1],
        &spine.leaves[LEAF_OUTPUT1_DATA],
    );
    bind_dead_pair(
        b,
        &bits[INPUT_SELECTORS + 1],
        &spine.leaves[LEAF_OUTPUT1_OWNER],
    );
    // User output amounts receive this exact proof in public_arithmetic.
    // Coinbase has no user-arithmetic instance, so prove its sole live amount
    // before the allocator packs the creation id into the high half.
    let amount = spine.leaves[LEAF_OUTPUT0_DATA][1].clone();
    let amount_bits: [Wire; 64] = range_check_bits(b, &amount, 64)
        .try_into()
        .expect("coinbase u64 range has exactly 64 bits");
    let action = selected_row(
        b,
        &bits[INPUT_SELECTORS],
        &spine.leaves[LEAF_OUTPUT0_DATA],
        &spine.leaves[LEAF_OUTPUT0_OWNER],
        true,
    );
    CoinbaseActionTrace {
        action,
        amount,
        amount_bits,
    }
}

/// Standalone compatibility wrapper. Production block assembly calls
/// [`bind_coinbase_action_with_amount`] so the reward ceiling can reuse the
/// exact source amount bits.
pub fn bind_coinbase_action(b: &mut FieldR1csBuilder, spine: &SpineInputsTrace) -> ActionRowTrace {
    bind_coinbase_action_with_amount(b, spine).action
}

/// Bind the fixed development-payout spine slot.
///
/// `live` is derived from the constrained child height, not supplied by the
/// prover. When live, the body is the exact two-output system-mint shape and
/// pays the two consensus recipients in fixed order. When dead, every raw leaf
/// equals the canonical protocol ghost body.
pub fn bind_development_payout_action(
    b: &mut FieldR1csBuilder,
    spine: &SpineInputsTrace,
    live: &LinExpr,
) -> DevelopmentPayoutActionTrace {
    let live_sq = mul(b, live, live);
    pin_eq(b, &live_sq, live);
    let dead = live.add_const(F128::ONE);
    let ghost =
        noid_gkr::spine_statement::spine_inputs_from_body(&noid_gkr::ghost_tx::ghost_tx_body());
    for leaf in 0..super::tx_body_spine::TX_BODY_RAW_LEAVES {
        for lane in 0..2 {
            let difference = spine.leaves[leaf][lane].add(&const_block(ghost.leaves[leaf][lane]));
            let gated = mul(b, &dead, &difference);
            pin_zero(b, &gated);
        }
    }

    let gate_expected = |b: &mut FieldR1csBuilder, actual: &LinExpr, expected: Block128| {
        let difference = actual.add(&const_block(expected));
        let gated = mul(b, live, &difference);
        pin_zero(b, &gated);
    };
    for lane in &spine.leaves[LEAF_FEE] {
        gate_expected(b, lane, Block128::ZERO);
    }
    for lane in &spine.leaves[LEAF_INPUT_OWNER] {
        gate_expected(b, lane, Block128::ZERO);
    }
    for input in 0..INPUT_SELECTORS {
        for lane in &spine.leaves[LEAF_INPUT_BASE + input] {
            gate_expected(b, lane, Block128::ZERO);
        }
    }
    gate_expected(
        b,
        &spine.leaves[LEAF_FLAGS][0],
        Block128::from((noid_tx::output_bitmap_bit(0) | noid_tx::output_bitmap_bit(1)) as u128),
    );
    gate_expected(b, &spine.leaves[LEAF_FLAGS][1], Block128::from(1u128));

    let recipients = [
        noid_chain::consensus::development_allocation::O1_NETWORK_FUND_ADDRESS,
        noid_chain::consensus::development_allocation::PARANO1D_LAB_ADDRESS,
    ];
    for (index, recipient) in recipients.iter().enumerate() {
        let owner_leaf = LEAF_OUTPUT0_OWNER + 2 * index;
        for (lane, expected) in recipient.as_fields().into_iter().enumerate() {
            gate_expected(b, &spine.leaves[owner_leaf][lane], expected);
        }
    }

    let first_amount = spine.leaves[LEAF_OUTPUT0_DATA][1].clone();
    let second_amount = spine.leaves[LEAF_OUTPUT1_DATA][1].clone();
    let amount_difference = first_amount.add(&second_amount);
    let gated_amount_difference = mul(b, live, &amount_difference);
    pin_zero(b, &gated_amount_difference);
    let _ = range_check_bits(b, &first_amount, 64);
    let _ = range_check_bits(b, &second_amount, 64);
    let amount_each = mul(b, live, &first_amount);

    let actions = std::array::from_fn(|index| {
        let data_leaf = LEAF_OUTPUT0_DATA + 2 * index;
        selected_row(
            b,
            live,
            &spine.leaves[data_leaf],
            &spine.leaves[data_leaf + 1],
            true,
        )
    });
    DevelopmentPayoutActionTrace {
        actions,
        amount_each,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acceptance::trace::tx_body_spine::SpineInputsTrace;
    use crate::acceptance::trace::{alloc_block, const_block};
    use noid_core::{Block128, TowerField};
    use noid_gkr::{spine_statement::spine_inputs_from_body, SpineInputs};
    use noid_poseidon2b::primitives::Address;
    use noid_tx::{output_bitmap_bit, TxBody, TxInput, TxOutput, TX_INPUTS, TX_OUTPUTS};

    fn body(owner: Address) -> TxBody {
        let mut inputs = [TxInput::dummy(); TX_INPUTS];
        inputs[0] = TxInput {
            slot_index: 7,
            amount: 20,
            creation_id: 3,
        };
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: 9,
            amount: 19,
            owner: Address([0x77; 32]),
        };
        TxBody {
            epoch_anchor: [0x42; 32],
            fee: 1,
            input_owner: owner,
            inputs,
            outputs,
            validity_bitmap: 1 | output_bitmap_bit(0),
            is_coinbase: false,
        }
    }

    fn edge_body(owner: Address) -> TxBody {
        let mut inputs = [TxInput::dummy(); TX_INPUTS];
        inputs[TX_INPUTS - 1] = TxInput {
            slot_index: 17,
            amount: 41,
            creation_id: 5,
        };
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[TX_OUTPUTS - 1] = TxOutput {
            slot_index: 19,
            amount: 40,
            owner: Address([0x88; 32]),
        };
        TxBody {
            epoch_anchor: [0x52; 32],
            fee: 1,
            input_owner: owner,
            inputs,
            outputs,
            validity_bitmap: (1 << (TX_INPUTS - 1)) | output_bitmap_bit(TX_OUTPUTS - 1),
            is_coinbase: false,
        }
    }

    fn coinbase_body() -> TxBody {
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: 23,
            amount: 50,
            owner: Address([0x99; 32]),
        };
        TxBody {
            epoch_anchor: [0x62; 32],
            fee: 0,
            input_owner: Address([0u8; 32]),
            inputs: [TxInput::dummy(); TX_INPUTS],
            outputs,
            validity_bitmap: output_bitmap_bit(0),
            is_coinbase: true,
        }
    }

    fn development_payout_body(amount: u64) -> TxBody {
        TxBody {
            epoch_anchor: [0x72; 32],
            fee: 0,
            input_owner: Address([0u8; 32]),
            inputs: [TxInput::dummy(); TX_INPUTS],
            outputs: [
                TxOutput {
                    slot_index: 24,
                    amount,
                    owner: noid_chain::consensus::O1_NETWORK_FUND_ADDRESS,
                },
                TxOutput {
                    slot_index: 25,
                    amount,
                    owner: noid_chain::consensus::PARANO1D_LAB_ADDRESS,
                },
            ],
            validity_bitmap: output_bitmap_bit(0) | output_bitmap_bit(1),
            is_coinbase: true,
        }
    }

    fn relation_satisfies(native: &SpineInputs, tx_live: Block128) -> bool {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut b = FieldR1csBuilder::new();
            let spine = SpineInputsTrace::alloc(&mut b, native);
            let tx_live = alloc_block(&mut b, tx_live);
            let _ = bind_user_action_surface(&mut b, &spine, &tx_live);
            let (r1cs, z) = b.build();
            r1cs.satisfies(&z)
        }))
        .unwrap_or(false)
    }

    fn coinbase_relation_satisfies(native: &SpineInputs) -> bool {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut b = FieldR1csBuilder::new();
            let spine = SpineInputsTrace::alloc(&mut b, native);
            let _ = bind_coinbase_action(&mut b, &spine);
            let (r1cs, z) = b.build();
            r1cs.satisfies(&z)
        }))
        .unwrap_or(false)
    }

    fn development_payout_relation_satisfies(native: &SpineInputs, live: Block128) -> bool {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut b = FieldR1csBuilder::new();
            let spine = SpineInputsTrace::alloc(&mut b, native);
            let live = alloc_block(&mut b, live);
            let _ = bind_development_payout_action(&mut b, &spine, &live);
            let (r1cs, z) = b.build();
            r1cs.satisfies(&z)
        }))
        .unwrap_or(false)
    }

    #[test]
    fn legacy_bitmap_rejects_contract_flags_without_changing_ordinary_rows() {
        let mut digest = None;
        for flag in [
            0,
            noid_tx::PAGED_SPEND_CONTRACT_BIT,
            noid_tx::PAGED_SPEND_TERMINAL_BIT,
        ] {
            let mut native_body = body(Address([0x33; 32]));
            native_body.validity_bitmap |= flag;
            let native = spine_inputs_from_body(&native_body);
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut b = FieldR1csBuilder::new();
                let spine = SpineInputsTrace::alloc(&mut b, &native);
                let surface = bind_user_action_surface_for_profile(
                    &mut b,
                    &spine,
                    &const_block(Block128::ONE),
                    false,
                );
                let (matrix, witness) = b.build();
                assert_eq!(surface.contract.eval(&witness), F128::ZERO);
                assert_eq!(surface.terminal.eval(&witness), F128::ZERO);
                (
                    matrix.structural_statement_digest(),
                    matrix.satisfies(&witness),
                )
            }));
            match result {
                Ok((actual, satisfies)) => {
                    assert_eq!(satisfies, flag == 0);
                    assert!(digest.is_none_or(|expected| expected == actual));
                    digest = Some(actual);
                }
                Err(_) => assert_ne!(flag, 0),
            }
        }
    }

    #[test]
    fn bitmap_drives_selectors_and_one_owner_pin() {
        let owner = Address([0x33; 32]);
        let native = spine_inputs_from_body(&body(owner));
        let mut b = FieldR1csBuilder::new();
        let spine = SpineInputsTrace::alloc(&mut b, &native);
        let surface = bind_user_action_surface(&mut b, &spine, &const_block(Block128::ONE));
        let (r1cs, z) = b.build();
        assert!(r1cs.satisfies(&z));
        assert_eq!(surface.raw_inputs[0].eval(&z), F128::ONE);
        assert_eq!(surface.raw_outputs[0].eval(&z), F128::ONE);
        assert!(surface.raw_inputs[1..]
            .iter()
            .all(|selector| selector.eval(&z) == F128::ZERO));
    }

    #[test]
    fn final_input_and_output_selectors_map_to_l10_and_l14() {
        let owner = Address([0x35; 32]);
        let native = spine_inputs_from_body(&edge_body(owner));
        let mut b = FieldR1csBuilder::new();
        let spine = SpineInputsTrace::alloc(&mut b, &native);
        let surface = bind_user_action_surface(&mut b, &spine, &const_block(Block128::ONE));
        let (r1cs, z) = b.build();
        assert!(r1cs.satisfies(&z));
        assert_eq!(surface.raw_inputs[TX_INPUTS - 1].eval(&z), F128::ONE);
        assert_eq!(surface.raw_outputs[TX_OUTPUTS - 1].eval(&z), F128::ONE);
        assert!(surface.raw_inputs[..TX_INPUTS - 1]
            .iter()
            .chain(&surface.raw_outputs[..TX_OUTPUTS - 1])
            .all(|selector| selector.eval(&z) == F128::ZERO));
    }

    #[test]
    fn page_surface_defers_owner_binding_to_paged_spend() {
        let native = spine_inputs_from_body(&body(Address([0x33; 32])));
        assert!(relation_satisfies(&native, Block128::ONE));
    }

    #[test]
    fn input_leaf_recombination_is_unsatisfied() {
        let owner = Address([0x35; 32]);
        let mut native = spine_inputs_from_body(&edge_body(owner));
        native
            .leaves
            .swap(LEAF_INPUT_BASE + TX_INPUTS - 1, LEAF_INPUT_BASE);
        assert!(!relation_satisfies(&native, Block128::ONE));
    }

    #[test]
    fn output_leaf_recombination_is_unsatisfied() {
        let owner = Address([0x35; 32]);
        let mut native = spine_inputs_from_body(&edge_body(owner));
        native.leaves.swap(LEAF_OUTPUT1_DATA, LEAF_OUTPUT0_DATA);
        native.leaves.swap(LEAF_OUTPUT1_OWNER, LEAF_OUTPUT0_OWNER);
        assert!(!relation_satisfies(&native, Block128::ONE));
    }

    #[test]
    fn outer_inactive_gates_counts() {
        let owner = Address([0x33; 32]);
        let native = spine_inputs_from_body(&body(owner));
        let mut b = FieldR1csBuilder::new();
        let spine = SpineInputsTrace::alloc(&mut b, &native);
        let surface = bind_user_action_surface(&mut b, &spine, &const_block(Block128::ZERO));
        let (r1cs, z) = b.build();
        assert!(r1cs.satisfies(&z));
        assert!(surface
            .selected_inputs
            .iter()
            .chain(&surface.selected_outputs)
            .all(|selector| selector.eval(&z) == F128::ZERO));
    }

    #[test]
    fn dead_nonzero_input_leaf_is_rejected() {
        let owner = Address([0x33; 32]);
        let mut native = spine_inputs_from_body(&body(owner));
        native.leaves[LEAF_INPUT_BASE + 1][1] = Block128::ONE;
        assert!(!relation_satisfies(&native, Block128::ONE));
    }

    #[test]
    fn dead_nonzero_output_data_leaf_is_rejected() {
        let owner = Address([0x33; 32]);
        let mut native = spine_inputs_from_body(&body(owner));
        native.leaves[LEAF_OUTPUT1_DATA][0] = Block128::ONE;
        assert!(!relation_satisfies(&native, Block128::ONE));
    }

    #[test]
    fn dead_nonzero_output_owner_is_rejected() {
        let owner = Address([0x33; 32]);
        let mut native = spine_inputs_from_body(&body(owner));
        native.leaves[LEAF_OUTPUT1_OWNER][1] = Block128::ONE;
        assert!(!relation_satisfies(&native, Block128::ONE));
    }

    #[test]
    fn user_coinbase_flag_is_rejected() {
        let owner = Address([0x33; 32]);
        let mut native = spine_inputs_from_body(&body(owner));
        native.leaves[LEAF_FLAGS][1] = Block128::ONE;
        assert!(!relation_satisfies(&native, Block128::ONE));
    }

    #[test]
    fn unused_high_validity_bit_is_rejected() {
        let owner = Address([0x33; 32]);
        let mut native = spine_inputs_from_body(&body(owner));
        native.leaves[LEAF_FLAGS][0] += Block128::from(1u128 << PAGE_VALIDITY_BITS);
        assert!(!relation_satisfies(&native, Block128::ONE));
    }

    #[test]
    fn outer_liveness_must_be_boolean() {
        let owner = Address([0x33; 32]);
        let native = spine_inputs_from_body(&body(owner));
        assert!(!relation_satisfies(&native, Block128::from(2u128)));
    }

    #[test]
    fn mandatory_coinbase_yields_one_mint_and_rejects_shape_tampering() {
        let native = spine_inputs_from_body(&coinbase_body());
        let mut b = FieldR1csBuilder::new();
        let spine = SpineInputsTrace::alloc(&mut b, &native);
        let row = bind_coinbase_action(&mut b, &spine);
        let (r1cs, z) = b.build();
        assert!(r1cs.satisfies(&z));
        assert_eq!(row.live.eval(&z), F128::ONE);
        assert_eq!(row.is_mint.eval(&z), F128::ONE);
        assert_eq!(
            row.slot_index.eval(&z),
            crate::acceptance::trace::flat_of(Block128::from(23u128))
        );

        for (leaf, lane) in [
            (LEAF_FEE, 0usize),
            (LEAF_INPUT_OWNER, 1),
            (LEAF_OUTPUT1_DATA, 0),
            (LEAF_OUTPUT1_OWNER, 1),
            (LEAF_FLAGS, 1),
        ] {
            let mut bad = native.clone();
            bad.leaves[leaf][lane] += Block128::ONE;
            assert!(
                !coinbase_relation_satisfies(&bad),
                "coinbase L{leaf}[{lane}] tamper accepted"
            );
        }

        let mut oversized_amount = native;
        oversized_amount.leaves[LEAF_OUTPUT0_DATA][1] = Block128::from(1u128 << 64);
        assert!(
            !coinbase_relation_satisfies(&oversized_amount),
            "coinbase amount above u64 bypassed the source range proof"
        );
    }

    #[test]
    fn development_payout_is_exact_when_live_and_canonical_ghost_when_dead() {
        let native = spine_inputs_from_body(&development_payout_body(123));
        let mut b = FieldR1csBuilder::new();
        let spine = SpineInputsTrace::alloc(&mut b, &native);
        let live = const_block(Block128::ONE);
        let payout = bind_development_payout_action(&mut b, &spine, &live);
        let (r1cs, z) = b.build();
        assert!(r1cs.satisfies(&z));
        assert_eq!(
            payout.amount_each.eval(&z),
            crate::acceptance::trace::flat_of(Block128::from(123u128))
        );
        assert!(payout.actions.iter().all(
            |action| action.live.eval(&z) == F128::ONE && action.is_mint.eval(&z) == F128::ONE
        ));

        let ghost = spine_inputs_from_body(&noid_gkr::ghost_tx::ghost_tx_body());
        assert!(development_payout_relation_satisfies(
            &ghost,
            Block128::ZERO
        ));
        assert!(!development_payout_relation_satisfies(
            &native,
            Block128::ZERO
        ));
        assert!(!development_payout_relation_satisfies(
            &native,
            Block128::from(2u128)
        ));
    }

    #[test]
    fn development_payout_rejects_any_shape_recipient_or_amount_tampering() {
        let native = spine_inputs_from_body(&development_payout_body(123));
        for (leaf, lane) in [
            (LEAF_FEE, 0usize),
            (LEAF_INPUT_OWNER, 1),
            (LEAF_INPUT_BASE, 1),
            (LEAF_FLAGS, 0),
            (LEAF_FLAGS, 1),
            (LEAF_OUTPUT0_OWNER, 0),
            (LEAF_OUTPUT1_OWNER, 1),
        ] {
            let mut bad = native.clone();
            bad.leaves[leaf][lane] += Block128::ONE;
            assert!(
                !development_payout_relation_satisfies(&bad, Block128::ONE),
                "development payout L{leaf}[{lane}] tamper accepted"
            );
        }

        let mut unequal_amounts = native.clone();
        unequal_amounts.leaves[LEAF_OUTPUT1_DATA][1] += Block128::ONE;
        assert!(!development_payout_relation_satisfies(
            &unequal_amounts,
            Block128::ONE
        ));

        let mut oversized_amount = native;
        oversized_amount.leaves[LEAF_OUTPUT0_DATA][1] = Block128::from(1u128 << 64);
        oversized_amount.leaves[LEAF_OUTPUT1_DATA][1] = Block128::from(1u128 << 64);
        assert!(
            !development_payout_relation_satisfies(&oversized_amount, Block128::ONE),
            "development payout amount above u64 bypassed the source range proof"
        );
    }
}

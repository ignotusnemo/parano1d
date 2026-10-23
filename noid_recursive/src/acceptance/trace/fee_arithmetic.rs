// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Checked block fee, burn, and coinbase arithmetic.
//!
//! Every logical-group count comes from the constrained START..END scanner,
//! whose page totals come from the exact selected bitmap expressions. Parent occupancy selects the consensus
//! pressure multiplier at the exact integer 50/75/90 percent boundaries;
//! child depth selects emission.  All monetary additions and comparisons are
//! unsigned tower-bit arithmetic.  In particular, no fee formula is evaluated
//! as characteristic-two field addition.

use noid_chain::consensus::fees::{PRESSURE_EXTREME_BPS, PRESSURE_HIGH_BPS, PRESSURE_LOW_BPS};
use noid_chain::consensus::params::{
    BASE_REWARD_MICRONOID, BLOCK_MAX_USER_PAGES, FEE_PER_INPUT, FEE_PER_OUTPUT, MIN_FEE_BASE,
    STATE_GROWTH_FEE_BASE,
};
use noid_core::{hardware::flat_to_tower_u128, Block128};

use super::exact_state::{StateDepthTrace, MAX_EXACT_STATE_DEPTH, MIN_EXACT_STATE_DEPTH};
use super::paged_spend::PagedSpendGroupTrace;
use super::{
    alloc_block, const_block, flat_const, mul, pin_eq, pin_zero, range_check_bits,
    FieldR1csBuilder, LinExpr, Wire, F128,
};

const U64_BITS: usize = 64;
const MONEY_SUM_BITS: usize = 72;
const SMALL_FEE_BITS: usize = 32;
const MAX_CONSERVATIVE_MIN_FEE: u128 = MIN_FEE_BASE as u128
    + FEE_PER_INPUT as u128 * noid_tx::MAX_PAGED_SPEND_INPUTS as u128
    + FEE_PER_OUTPUT as u128 * noid_tx::MAX_PAGED_SPEND_OUTPUTS as u128
    + STATE_GROWTH_FEE_BASE as u128 * 8 * noid_tx::MAX_PAGED_SPEND_OUTPUTS as u128;
const MAX_BLOCK_COINBASE_CEILING: u128 =
    BLOCK_MAX_USER_PAGES as u128 * u64::MAX as u128 + BASE_REWARD_MICRONOID as u128;
const _: () = assert!(MAX_CONSERVATIVE_MIN_FEE < (1u128 << SMALL_FEE_BITS));
const _: () = assert!(MAX_BLOCK_COINBASE_CEILING < (1u128 << MONEY_SUM_BITS));

/// Fee facts proven for one logical PagedSpend group. Capacity ghosts have
/// zero counts, minimum, burn, and claimable contribution.
pub struct LogicalGroupFeeArithmeticTrace {
    pub live_input_count: LinExpr,
    pub live_output_count: LinExpr,
    pub minimum_fee: LinExpr,
    pub burned_fee: LinExpr,
    pub claimable_fee: LinExpr,
    pub claimable_bits: [Wire; U64_BITS],
}

/// Block-level fee/reward result. `pressure_multiplier` and
/// `claimable_fee_sum` are explicit pinned wires so witness-only negative
/// tests can target the semantic handoff directly.
pub struct BlockFeeArithmeticTrace {
    pub pressure_multiplier: LinExpr,
    pub groups: Vec<LogicalGroupFeeArithmeticTrace>,
    pub claimable_fee_sum: LinExpr,
    pub block_reward: LinExpr,
    pub coinbase_subsidy: LinExpr,
    pub max_coinbase_value: LinExpr,
}

fn tower_value(b: &FieldR1csBuilder, expr: &LinExpr) -> u128 {
    let flat = expr.eval(b.values());
    flat_to_tower_u128((flat.lo as u128) | ((flat.hi as u128) << 64))
}

fn reconstruct_bits(bits: &[LinExpr]) -> LinExpr {
    assert!(bits.len() <= 128);
    bits.iter()
        .enumerate()
        .fold(LinExpr::zero(), |sum, (bit, value)| {
            sum.add(&value.scale(flat_const(1u128 << bit)))
        })
}

/// Ripple-carry integer addition over semantic boolean expressions. The
/// result bits stay boolean because the two carry products are disjoint.
fn checked_add_bits(b: &mut FieldR1csBuilder, lhs: &[LinExpr], rhs: &[LinExpr]) -> Vec<LinExpr> {
    assert_eq!(lhs.len(), rhs.len());
    let mut carry = LinExpr::zero();
    let mut sum = Vec::with_capacity(lhs.len());
    for (a, c) in lhs.iter().zip(rhs) {
        sum.push(a.add(c).add(&carry));
        let a_c = mul(b, a, c);
        let carry_axc = mul(b, &carry, &a.add(c));
        carry = a_c.add(&carry_axc);
    }
    pin_zero(b, &carry);
    sum
}

/// Final borrow of `lhs - rhs`, hence the exact unsigned predicate
/// `lhs < rhs`. This two-product recurrence is evaluated LSB first.
fn less_than_bits(b: &mut FieldR1csBuilder, lhs: &[LinExpr], rhs: &[LinExpr]) -> LinExpr {
    assert_eq!(lhs.len(), rhs.len());
    let mut borrow = LinExpr::zero();
    for (a, c) in lhs.iter().zip(rhs) {
        // borrow' = (!a & c) OR (borrow & (a == c)). The two terms cannot
        // both be one, so characteristic-two addition is exact OR here.
        let not_a_c = mul(b, &a.add_const(F128::ONE), c);
        let borrow_eq = mul(b, &borrow, &a.add(c).add_const(F128::ONE));
        borrow = not_a_c.add(&borrow_eq);
    }
    borrow
}

fn selected_constant_bits(selectors: &[LinExpr], constants: &[u64], width: usize) -> Vec<LinExpr> {
    assert_eq!(selectors.len(), constants.len());
    (0..width)
        .map(|bit| {
            selectors
                .iter()
                .zip(constants)
                .filter(|(_, constant)| bit < u64::BITS as usize && (**constant >> bit) & 1 == 1)
                .fold(LinExpr::zero(), |sum, (selector, _)| sum.add(selector))
        })
        .collect()
}

/// Smallest active-slot count whose native floor-basis-point occupancy is at
/// least `threshold_bps`.
fn occupancy_threshold(depth: usize, threshold_bps: u64) -> u64 {
    let capacity = 1u128 << depth;
    let numerator = capacity * u128::from(threshold_bps);
    numerator.div_ceil(10_000) as u64
}

fn depth_selected_threshold_bits(depth: &StateDepthTrace, threshold_bps: u64) -> Vec<LinExpr> {
    let constants: Vec<u64> = (MIN_EXACT_STATE_DEPTH..=MAX_EXACT_STATE_DEPTH)
        .map(|d| occupancy_threshold(d, threshold_bps))
        .collect();
    selected_constant_bits(&depth.one_hot, &constants, U64_BITS)
}

fn bind_pressure(
    b: &mut FieldR1csBuilder,
    parent_active_count: &LinExpr,
    parent_depth: &StateDepthTrace,
) -> (LinExpr, [LinExpr; 4]) {
    let active_bits: Vec<LinExpr> = range_check_bits(b, parent_active_count, U64_BITS)
        .into_iter()
        .map(LinExpr::from_wire)
        .collect();
    let low = depth_selected_threshold_bits(parent_depth, PRESSURE_LOW_BPS);
    let high = depth_selected_threshold_bits(parent_depth, PRESSURE_HIGH_BPS);
    let extreme = depth_selected_threshold_bits(parent_depth, PRESSURE_EXTREME_BPS);

    let below_low = less_than_bits(b, &active_bits, &low);
    let below_high = less_than_bits(b, &active_bits, &high);
    let below_extreme = less_than_bits(b, &active_bits, &extreme);
    // The exact disjoint pressure intervals: <50, [50,75), [75,90), >=90.
    let regions = [
        below_low.clone(),
        below_low.add(&below_high),
        below_high.add(&below_extreme),
        below_extreme.add_const(F128::ONE),
    ];
    let multipliers = [1u64, 2, 4, 8];
    let derived = reconstruct_bits(&selected_constant_bits(&regions, &multipliers, 4));

    let native_active = tower_value(b, parent_active_count) as u64;
    let native_depth = tower_value(b, &parent_depth.value) as u32;
    let native = noid_chain::consensus::fees::pressure_multiplier(native_active, native_depth);
    let pressure = alloc_block(b, Block128::from(native as u128));
    pin_eq(b, &pressure, &derived);
    (pressure, regions)
}

fn constant_product_bits(
    b: &mut FieldR1csBuilder,
    value_bits: &[LinExpr],
    constant: u64,
    width: usize,
) -> Vec<LinExpr> {
    let mut product = vec![LinExpr::zero(); width];
    let mut initialized = false;
    for shift in 0..u64::BITS as usize {
        if (constant >> shift) & 1 == 0 {
            continue;
        }
        let mut term = vec![LinExpr::zero(); width];
        for (bit, value) in value_bits.iter().enumerate() {
            if bit + shift < width {
                term[bit + shift] = value.clone();
            }
        }
        if initialized {
            product = checked_add_bits(b, &product, &term);
        } else {
            product = term;
            initialized = true;
        }
    }
    product
}

fn bind_group_fee(
    b: &mut FieldR1csBuilder,
    group: &PagedSpendGroupTrace,
    pressure_regions: &[LinExpr; 4],
) -> LogicalGroupFeeArithmeticTrace {
    bind_group_fee_rule(b, group, pressure_regions, None)
}
fn bind_group_fee_rule(
    b: &mut FieldR1csBuilder,
    group: &PagedSpendGroupTrace,
    pressure_regions: &[LinExpr; 4],
    rule: Option<&FinancialGroupFeeRuleTrace>,
) -> LogicalGroupFeeArithmeticTrace {
    let live_input_count = group.live_input_count.clone();
    let live_output_count = group.live_output_count.clone();
    let input_bits_wires = range_check_bits(b, &live_input_count, 11);
    let output_bits_wires = range_check_bits(b, &live_output_count, 9);
    let input_cap = range_check_bits(
        b,
        &const_block(Block128::from(
            (noid_tx::MAX_PAGED_SPEND_INPUTS + 1) as u128,
        )),
        11,
    );
    let output_cap = range_check_bits(
        b,
        &const_block(Block128::from(
            (noid_tx::MAX_PAGED_SPEND_OUTPUTS + 1) as u128,
        )),
        9,
    );
    super::pin_lt_strict(b, &input_bits_wires, &input_cap);
    super::pin_lt_strict(b, &output_bits_wires, &output_cap);
    let input_bits = input_bits_wires
        .iter()
        .copied()
        .map(LinExpr::from_wire)
        .collect::<Vec<_>>();
    let output_bits = output_bits_wires
        .iter()
        .copied()
        .map(LinExpr::from_wire)
        .collect::<Vec<_>>();
    let input_fee_bits = constant_product_bits(b, &input_bits, FEE_PER_INPUT, SMALL_FEE_BITS);
    let output_fee_bits = constant_product_bits(b, &output_bits, FEE_PER_OUTPUT, SMALL_FEE_BITS);
    let base_bits: Vec<LinExpr> = (0..SMALL_FEE_BITS)
        .map(|bit| {
            if (MIN_FEE_BASE >> bit) & 1 == 1 {
                group.live.clone()
            } else {
                LinExpr::zero()
            }
        })
        .collect();

    // net = max(0, outputs-inputs). The strict comparison is derived from the
    // same count bits; the native net wire is constrained to zero on the
    // non-growth arm and to `input + net = output` on the growth arm.
    let mut input_wide = input_bits.clone();
    input_wide.resize(11, LinExpr::zero());
    let mut output_wide = output_bits.clone();
    output_wide.resize(11, LinExpr::zero());
    let is_growth = less_than_bits(b, &input_wide, &output_wide);
    let input_native = tower_value(b, &live_input_count);
    let output_native = tower_value(b, &live_output_count);
    let net_native = output_native.saturating_sub(input_native);
    let net = alloc_block(b, Block128::from(net_native));
    let net_wires = range_check_bits(b, &net, 9);
    let net_bits = net_wires
        .iter()
        .copied()
        .map(LinExpr::from_wire)
        .collect::<Vec<_>>();
    let dead_net = mul(b, &is_growth.add_const(F128::ONE), &net);
    pin_zero(b, &dead_net);
    let mut net_wide = net_bits.clone();
    net_wide.resize(11, LinExpr::zero());
    let input_plus_net = reconstruct_bits(&checked_add_bits(b, &input_wide, &net_wide));
    let bad_net = mul(b, &is_growth, &input_plus_net.add(&live_output_count));
    pin_zero(b, &bad_net);

    let base_burn = constant_product_bits(b, &net_bits, STATE_GROWTH_FEE_BASE, SMALL_FEE_BITS);
    let mut burn_bits = vec![LinExpr::zero(); SMALL_FEE_BITS];
    for (region_index, region) in pressure_regions.iter().enumerate() {
        for bit in 0..SMALL_FEE_BITS {
            if bit >= region_index {
                burn_bits[bit] =
                    burn_bits[bit].add(&mul(b, region, &base_burn[bit - region_index]));
            }
        }
    }
    let burned_fee = reconstruct_bits(&burn_bits);

    let base_and_inputs = checked_add_bits(b, &base_bits, &input_fee_bits);
    let base_io = checked_add_bits(b, &base_and_inputs, &output_fee_bits);
    let minimum_bits = checked_add_bits(b, &base_io, &burn_bits);
    let minimum_fee = reconstruct_bits(&minimum_bits);

    // Existing public-arithmetic fee bits are the sole fee decomposition.
    let mut minimum_wide = minimum_bits;
    minimum_wide.resize(U64_BITS, LinExpr::zero());
    let fee_wires = range_check_bits(b, &group.fee, U64_BITS);
    let fee_bits: Vec<LinExpr> = fee_wires.iter().copied().map(LinExpr::from_wire).collect();
    let fee_below_minimum = less_than_bits(b, &fee_bits, &minimum_wide);
    if let Some(rule) = rule {
        let invalid = mul(b, &rule.waived, &group.fee);
        pin_zero(b, &invalid);
        let active_floor = mul(b, &rule.waived.add_const(F128::ONE), &fee_below_minimum);
        pin_zero(b, &active_floor);
        let different = mul(b, &rule.exact, &group.fee.add(&minimum_fee));
        pin_zero(b, &different);
    } else {
        pin_zero(b, &fee_below_minimum);
    }

    // claimable + burn = tx_live*fee, with a checked u64 carry chain. A ghost
    // therefore contributes exactly zero even if a standalone caller supplies
    // a nonzero canonical raw fee body behind tx_live=0.
    let paid_native = tower_value(b, &group.fee);
    let burn_native = tower_value(b, &burned_fee);
    let claimable_native = paid_native.checked_sub(burn_native).unwrap_or(0);
    let claimable_fee = alloc_block(b, Block128::from(claimable_native));
    let claimable_bits: [Wire; U64_BITS] = range_check_bits(b, &claimable_fee, U64_BITS)
        .try_into()
        .expect("claimable u64 range has exactly 64 bits");
    let claimable_expr_bits: Vec<LinExpr> = claimable_bits
        .iter()
        .copied()
        .map(LinExpr::from_wire)
        .collect();
    let mut burn_wide = burn_bits;
    burn_wide.resize(U64_BITS, LinExpr::zero());
    let paid_reconstruction =
        reconstruct_bits(&checked_add_bits(b, &claimable_expr_bits, &burn_wide));
    pin_eq(b, &paid_reconstruction, &group.fee);

    let minimum_fee = if let Some(rule) = rule {
        mul(b, &rule.waived.add_const(F128::ONE), &minimum_fee)
    } else {
        minimum_fee
    };
    LogicalGroupFeeArithmeticTrace {
        live_input_count,
        live_output_count,
        minimum_fee,
        burned_fee,
        claimable_fee,
        claimable_bits,
    }
}

/// Bind all user fee predicates, checked 72-bit claimable aggregation, and
/// `coinbase <= reward(child_depth) + claimable_sum`. Underclaiming is valid.
pub fn bind_block_fee_arithmetic(
    b: &mut FieldR1csBuilder,
    groups: &[PagedSpendGroupTrace],
    parent_active_count: &LinExpr,
    parent_depth: &StateDepthTrace,
    child_depth: &StateDepthTrace,
    coinbase_subsidy: &LinExpr,
    coinbase_amount: &LinExpr,
    coinbase_amount_bits: &[Wire; U64_BITS],
) -> BlockFeeArithmeticTrace {
    bind_block_fee_arithmetic_inner(
        b,
        groups,
        parent_active_count,
        parent_depth,
        child_depth,
        coinbase_subsidy,
        coinbase_amount,
        coinbase_amount_bits,
        None,
    )
}
fn bind_block_fee_arithmetic_inner(
    b: &mut FieldR1csBuilder,
    groups: &[PagedSpendGroupTrace],
    parent_active_count: &LinExpr,
    parent_depth: &StateDepthTrace,
    child_depth: &StateDepthTrace,
    coinbase_subsidy: &LinExpr,
    coinbase_amount: &LinExpr,
    coinbase_amount_bits: &[Wire; U64_BITS],
    rules: Option<&[FinancialGroupFeeRuleTrace]>,
) -> BlockFeeArithmeticTrace {
    let (pressure_multiplier, pressure_regions) =
        bind_pressure(b, parent_active_count, parent_depth);
    let groups: Vec<LogicalGroupFeeArithmeticTrace> = groups
        .iter()
        .enumerate()
        .map(|(i, group)| {
            if let Some(rules) = rules {
                bind_group_fee_rule(b, group, &pressure_regions, Some(&rules[i]))
            } else {
                bind_group_fee(b, group, &pressure_regions)
            }
        })
        .collect();

    let mut aggregate_bits = vec![LinExpr::zero(); MONEY_SUM_BITS];
    if let Some((first, rest)) = groups.split_first() {
        for (dst, bit) in aggregate_bits.iter_mut().zip(&first.claimable_bits) {
            *dst = LinExpr::from_wire(*bit);
        }
        for user in rest {
            let mut term: Vec<LinExpr> = user
                .claimable_bits
                .iter()
                .copied()
                .map(LinExpr::from_wire)
                .collect();
            term.resize(MONEY_SUM_BITS, LinExpr::zero());
            aggregate_bits = checked_add_bits(b, &aggregate_bits, &term);
        }
    }
    let aggregate_reconstruction = reconstruct_bits(&aggregate_bits);
    let aggregate_native = tower_value(b, &aggregate_reconstruction);
    let claimable_fee_sum = alloc_block(b, Block128::from(aggregate_native));
    pin_eq(b, &claimable_fee_sum, &aggregate_reconstruction);

    let rewards: Vec<u64> = (MIN_EXACT_STATE_DEPTH..=MAX_EXACT_STATE_DEPTH)
        .map(|depth| noid_chain::consensus::emission::block_reward(depth as u32))
        .collect();
    let reward_bits = selected_constant_bits(&child_depth.one_hot, &rewards, MONEY_SUM_BITS);
    let block_reward = reconstruct_bits(&reward_bits);
    let mut subsidy_bits: Vec<LinExpr> = range_check_bits(b, coinbase_subsidy, U64_BITS)
        .into_iter()
        .map(LinExpr::from_wire)
        .collect();
    subsidy_bits.resize(MONEY_SUM_BITS, LinExpr::zero());
    let max_bits = checked_add_bits(b, &aggregate_bits, &subsidy_bits);
    let max_coinbase_value = reconstruct_bits(&max_bits);

    let mut coinbase_bits: Vec<LinExpr> = coinbase_amount_bits
        .iter()
        .copied()
        .map(LinExpr::from_wire)
        .collect();
    pin_eq(b, coinbase_amount, &reconstruct_bits(&coinbase_bits));
    coinbase_bits.resize(MONEY_SUM_BITS, LinExpr::zero());
    let overclaim = less_than_bits(b, &max_bits, &coinbase_bits);
    pin_zero(b, &overclaim);

    BlockFeeArithmeticTrace {
        pressure_multiplier,
        groups,
        claimable_fee_sum,
        block_reward,
        coinbase_subsidy: coinbase_subsidy.clone(),
        max_coinbase_value,
    }
}

pub struct FinancialGroupFeeRuleTrace {
    pub waived: LinExpr,
    pub exact: LinExpr,
}
pub struct FinancialBlockFeeArithmeticTrace {
    pub block: BlockFeeArithmeticTrace,
    pub required_by_header: Vec<LinExpr>,
}

fn checked_count(b: &mut FieldR1csBuilder, x: &[LinExpr], hit: &LinExpr) -> Vec<LinExpr> {
    let mut y = vec![LinExpr::zero(); x.len()];
    y[0] = hit.clone();
    checked_add_bits(b, x, &y)
}
fn zero(b: &mut FieldR1csBuilder, x: &LinExpr) -> LinExpr {
    super::native_assets::validation::is_zero(b, x)
}
fn when_equal(b: &mut FieldR1csBuilder, hit: &LinExpr, a: &LinExpr, c: &LinExpr) {
    let bad = mul(b, hit, &a.add(c));
    pin_zero(b, &bad);
}

/// Bind the complete native header/group join, public exact fees and zero-fee
/// registration/reset maintenance. Launch settlement supplies its additional
/// rounding charge in its exact transition kernel. The same actual I/O counts
/// determine State-growth burn and claimable block fees.
pub fn bind_financial_block_fee_arithmetic(
    b: &mut FieldR1csBuilder,
    groups: &[PagedSpendGroupTrace],
    native_groups: &[LinExpr],
    headers: &[super::native_assets::header::FinancialNativeHeaderTrace],
    parent_active_count: &LinExpr,
    parent_depth: &StateDepthTrace,
    child_depth: &StateDepthTrace,
    coinbase_subsidy: &LinExpr,
    coinbase_amount: &LinExpr,
    coinbase_amount_bits: &[Wire; U64_BITS],
) -> FinancialBlockFeeArithmeticTrace {
    assert_eq!(groups.len(), native_groups.len());
    let hwidth = (headers.len() + 1)
        .next_power_of_two()
        .trailing_zeros()
        .max(1) as usize;
    let gwidth = (groups.len() + 1)
        .next_power_of_two()
        .trailing_zeros()
        .max(1) as usize;
    let mut header_counts = vec![vec![LinExpr::zero(); gwidth]; headers.len()];
    let mut hits = Vec::new();
    let mut rules = Vec::new();
    for (i, g) in groups.iter().enumerate() {
        let flag = &native_groups[i];
        let invalid = mul(b, flag, &flag.add_const(F128::ONE));
        pin_zero(b, &invalid);
        let outside = mul(b, flag, &g.live.add_const(F128::ONE));
        pin_zero(b, &outside);
        let mut count = vec![LinExpr::zero(); hwidth];
        let (mut waived, mut exact) = (LinExpr::zero(), LinExpr::zero());
        let mut row = Vec::new();
        for (j, h) in headers.iter().enumerate() {
            let same0 = zero(b, &g.logical_txid[0].add(&h.header.logical_txid[0]));
            let same1 = zero(b, &g.logical_txid[1].add(&h.header.logical_txid[1]));
            let hit = mul(b, &same0, &same1);
            let hit = mul(b, &hit, &g.live);
            let hit = mul(b, &hit, &h.header.live);
            count = checked_count(b, &count, &hit);
            header_counts[j] = checked_count(b, &header_counts[j], &hit);
            for (a, c) in [
                (&g.fee, &h.header.fee),
                (&g.live_input_count, &h.header.input_count),
                (&g.live_output_count, &h.header.output_count),
                (&g.input_owner[0], &h.header.authority[0]),
                (&g.input_owner[1], &h.header.authority[1]),
            ] {
                when_equal(b, &hit, a, c);
            }
            let selected = |code| {
                h.metadata.financial
                    [super::native_assets::financial_operation::FINANCIAL_OPERATION_CODES
                        .iter()
                        .position(|&c| c == code)
                        .unwrap()]
                .clone()
            };
            let hzero = noid_tx::native_assets::financial::ZERO_FEE_OPERATION_CODES
                .into_iter()
                .fold(LinExpr::zero(), |s, c| s.add(&selected(c)));
            let hexact = h
                .header
                .live
                .add(&h.metadata.owner_required)
                .add(&selected(51))
                .add(&selected(80))
                .add(&hzero);
            waived = waived.add(&mul(b, &hit, &hzero));
            exact = exact.add(&mul(b, &hit, &hexact));
            row.push(hit);
        }
        pin_eq(b, &reconstruct_bits(&count), flag);
        rules.push(FinancialGroupFeeRuleTrace { waived, exact });
        hits.push(row);
    }
    for (j, h) in headers.iter().enumerate() {
        pin_eq(b, &reconstruct_bits(&header_counts[j]), &h.header.live);
    }
    let block = bind_block_fee_arithmetic_inner(
        b,
        groups,
        parent_active_count,
        parent_depth,
        child_depth,
        coinbase_subsidy,
        coinbase_amount,
        coinbase_amount_bits,
        Some(&rules),
    );
    let required_by_header = (0..headers.len())
        .map(|j| {
            block
                .groups
                .iter()
                .enumerate()
                .fold(LinExpr::zero(), |sum, (i, g)| {
                    sum.add(&mul(b, &hits[i][j], &g.minimum_fee))
                })
        })
        .collect();
    FinancialBlockFeeArithmeticTrace {
        block,
        required_by_header,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_ivc_core::field_r1cs::FieldR1cs;
    use noid_poseidon2b::primitives::Address;
    use noid_tx::{output_bitmap_bit, TxBody, TxInput, TxOutput, TX_INPUTS, TX_OUTPUTS};

    fn body(n_inputs: usize, n_outputs: usize, fee: u64) -> TxBody {
        assert!((1..=TX_INPUTS).contains(&n_inputs));
        assert!((1..=TX_OUTPUTS).contains(&n_outputs));
        let mut inputs = [TxInput::dummy(); TX_INPUTS];
        for (index, input) in inputs.iter_mut().take(n_inputs).enumerate() {
            *input = TxInput {
                slot_index: 10 + index as u32,
                amount: 100_000,
                creation_id: 100 + index as u64,
            };
        }
        let input_sum = n_inputs as u64 * 100_000;
        let spendable = input_sum.checked_sub(fee).expect("test fee fits");
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        let mut remaining = spendable;
        for (index, output) in outputs.iter_mut().take(n_outputs).enumerate() {
            let amount = if index + 1 == n_outputs {
                remaining
            } else {
                spendable / n_outputs as u64
            };
            remaining -= amount;
            *output = TxOutput {
                slot_index: 100 + index as u32,
                amount,
                owner: Address([0x70 + index as u8; 32]),
            };
        }
        let input_bitmap = (1u16 << n_inputs) - 1;
        let output_bitmap = (0..n_outputs).fold(0, |bits, i| bits | output_bitmap_bit(i));
        TxBody {
            epoch_anchor: [0x42; 32],
            fee,
            input_owner: Address([0x33; 32]),
            inputs,
            outputs,
            validity_bitmap: input_bitmap | output_bitmap,
            is_coinbase: false,
        }
    }

    fn required(body: &TxBody, active: u64, depth: u32) -> u64 {
        noid_chain::consensus::fees::required_fee_for_tx_body(body, active, depth)
    }

    fn claimable(body: &TxBody, active: u64, depth: u32) -> u64 {
        noid_chain::consensus::fees::claimable_fee_for_tx_body(body, active, depth)
    }

    fn build_case(
        bodies: &[TxBody],
        parent_active: u64,
        parent_depth: u32,
        child_depth: u32,
        coinbase: u64,
    ) -> (FieldR1cs, Vec<F128>, BlockFeeArithmeticTrace) {
        build_case_with_liveness(
            bodies,
            &vec![true; bodies.len()],
            parent_active,
            parent_depth,
            child_depth,
            coinbase,
        )
    }

    fn build_case_with_liveness(
        bodies: &[TxBody],
        liveness: &[bool],
        parent_active: u64,
        parent_depth: u32,
        child_depth: u32,
        coinbase: u64,
    ) -> (FieldR1cs, Vec<F128>, BlockFeeArithmeticTrace) {
        assert_eq!(bodies.len(), liveness.len());
        let child_depth_native = child_depth;
        let mut b = FieldR1csBuilder::new();
        let parent_active = alloc_block(&mut b, Block128::from(parent_active as u128));
        let parent_depth_value = alloc_block(&mut b, Block128::from(parent_depth as u128));
        let child_depth_value = alloc_block(&mut b, Block128::from(child_depth as u128));
        let parent_depth = StateDepthTrace::bind(&mut b, &parent_depth_value);
        let child_depth = StateDepthTrace::bind(&mut b, &child_depth_value);
        let groups: Vec<_> = bodies
            .iter()
            .zip(liveness)
            .map(|(body, &is_live)| {
                let live = alloc_block(&mut b, Block128::from(u128::from(is_live)));
                PagedSpendGroupTrace {
                    live,
                    logical_txid: [LinExpr::zero(), LinExpr::zero()],
                    input_owner: [LinExpr::zero(), LinExpr::zero()],
                    fee: alloc_block(
                        &mut b,
                        Block128::from(if is_live { body.fee as u128 } else { 0 }),
                    ),
                    live_input_count: alloc_block(
                        &mut b,
                        Block128::from(if is_live {
                            body.live_input_count() as u128
                        } else {
                            0
                        }),
                    ),
                    live_output_count: alloc_block(
                        &mut b,
                        Block128::from(if is_live {
                            body.live_output_count() as u128
                        } else {
                            0
                        }),
                    ),
                    end_page: LinExpr::zero(),
                }
            })
            .collect();
        let coinbase = alloc_block(&mut b, Block128::from(coinbase as u128));
        let subsidy = alloc_block(
            &mut b,
            Block128::from(
                noid_chain::consensus::emission::block_reward(child_depth_native) as u128,
            ),
        );
        let coinbase_bits: [Wire; U64_BITS] = range_check_bits(&mut b, &coinbase, U64_BITS)
            .try_into()
            .expect("u64 bits");
        let trace = bind_block_fee_arithmetic(
            &mut b,
            &groups,
            &parent_active,
            &parent_depth,
            &child_depth,
            &subsidy,
            &coinbase,
            &coinbase_bits,
        );
        let (r1cs, witness) = b.build();
        (r1cs, witness, trace)
    }

    fn value(witness: &[F128], expr: &LinExpr) -> u128 {
        let flat = expr.eval(witness);
        flat_to_tower_u128((flat.lo as u128) | ((flat.hi as u128) << 64))
    }

    #[test]
    fn honest_fee_burn_claimable_and_underclaimed_coinbase() {
        let depth = 24u32;
        let active = occupancy_threshold(depth as usize, PRESSURE_EXTREME_BPS);
        let provisional = body(1, 2, 0);
        let fee = required(&provisional, active, depth);
        let body = body(1, 2, fee);
        let claimable = claimable(&body, active, depth);
        let reward = noid_chain::consensus::emission::block_reward(depth);
        let coinbase = reward + claimable - 1;
        let (r1cs, witness, trace) = build_case(&[body], active, depth, depth, coinbase);
        assert!(r1cs.satisfies(&witness));
        assert_eq!(value(&witness, &trace.pressure_multiplier), 8);
        assert_eq!(value(&witness, &trace.groups[0].minimum_fee), fee as u128);
        assert_eq!(value(&witness, &trace.groups[0].burned_fee), 20_000);
        assert_eq!(
            value(&witness, &trace.groups[0].claimable_fee),
            claimable as u128
        );
        assert_eq!(value(&witness, &trace.claimable_fee_sum), claimable as u128);
        assert_eq!(value(&witness, &trace.block_reward), reward as u128);
        assert_eq!(
            value(&witness, &trace.max_coinbase_value),
            (reward + claimable) as u128
        );
    }

    #[test]
    fn fee_below_exact_minimum_is_rejected() {
        let depth = 24u32;
        let provisional = body(1, 2, 0);
        let minimum = required(&provisional, 0, depth);
        let bad = body(1, 2, minimum - 1);
        let (r1cs, witness, _) = build_case(&[bad], 0, depth, depth, 0);
        assert!(!r1cs.satisfies(&witness));
    }

    #[test]
    fn wrong_pressure_and_claimable_aggregate_witnesses_are_rejected() {
        let depth = 24u32;
        let active = occupancy_threshold(depth as usize, PRESSURE_EXTREME_BPS);
        let provisional = body(1, 2, 0);
        let fee = required(&provisional, active, depth);
        let body = body(1, 2, fee);
        let claimable = claimable(&body, active, depth);
        let reward = noid_chain::consensus::emission::block_reward(depth);
        let (r1cs, witness, trace) = build_case(&[body], active, depth, depth, reward + claimable);
        assert!(r1cs.satisfies(&witness));

        let pressure_wire = trace.pressure_multiplier.terms[0].0 as usize;
        let mut wrong_pressure = witness.clone();
        wrong_pressure[pressure_wire] += F128::ONE;
        assert!(!r1cs.satisfies(&wrong_pressure));

        let aggregate_wire = trace.claimable_fee_sum.terms[0].0 as usize;
        let mut wrong_aggregate = witness;
        wrong_aggregate[aggregate_wire] += F128::ONE;
        assert!(!r1cs.satisfies(&wrong_aggregate));
    }

    #[test]
    fn coinbase_reward_overclaim_is_rejected() {
        let depth = 24u32;
        let provisional = body(1, 1, 0);
        let fee = required(&provisional, 0, depth);
        let body = body(1, 1, fee);
        let maximum =
            noid_chain::consensus::emission::block_reward(depth) + claimable(&body, 0, depth);
        let (r1cs, witness, _) = build_case(&[body], 0, depth, depth, maximum + 1);
        assert!(!r1cs.satisfies(&witness));
    }

    #[test]
    fn exact_pressure_boundaries_match_native_integer_basis_points() {
        for depth in MIN_EXACT_STATE_DEPTH..=MAX_EXACT_STATE_DEPTH {
            for (bps, before, at) in [
                (PRESSURE_LOW_BPS, 1, 2),
                (PRESSURE_HIGH_BPS, 2, 4),
                (PRESSURE_EXTREME_BPS, 4, 8),
            ] {
                let threshold = occupancy_threshold(depth, bps);
                assert_eq!(
                    noid_chain::consensus::fees::pressure_multiplier(threshold - 1, depth as u32),
                    before
                );
                assert_eq!(
                    noid_chain::consensus::fees::pressure_multiplier(threshold, depth as u32),
                    at
                );
            }
        }
    }

    #[test]
    fn pressure_boundary_circuit_matches_native_at_every_step() {
        let depth = MIN_EXACT_STATE_DEPTH as u32;
        for (bps, before, at) in [
            (PRESSURE_LOW_BPS, 1u128, 2u128),
            (PRESSURE_HIGH_BPS, 2, 4),
            (PRESSURE_EXTREME_BPS, 4, 8),
        ] {
            let threshold = occupancy_threshold(depth as usize, bps);
            for (active, expected) in [(threshold - 1, before), (threshold, at)] {
                let provisional = body(1, 2, 0);
                let fee = required(&provisional, active, depth);
                let user = body(1, 2, fee);
                let (r1cs, witness, trace) = build_case(&[user], active, depth, depth, 0);
                assert!(r1cs.satisfies(&witness), "bps={bps} active={active}");
                assert_eq!(
                    value(&witness, &trace.pressure_multiplier),
                    expected,
                    "bps={bps} active={active}"
                );
            }
        }
    }

    #[test]
    fn every_child_depth_selects_the_native_reward() {
        for depth in MIN_EXACT_STATE_DEPTH as u32..=MAX_EXACT_STATE_DEPTH as u32 {
            let provisional = body(1, 1, 0);
            let fee = required(&provisional, 0, depth);
            let user = body(1, 1, fee);
            let claimable = claimable(&user, 0, depth);
            let reward = noid_chain::consensus::emission::block_reward(depth);
            let (r1cs, witness, trace) = build_case(&[user], 0, depth, depth, reward + claimable);
            assert!(r1cs.satisfies(&witness), "child depth {depth}");
            assert_eq!(value(&witness, &trace.block_reward), reward as u128);
            assert_eq!(
                value(&witness, &trace.max_coinbase_value),
                (reward + claimable) as u128
            );
        }
    }

    #[test]
    fn matrix_is_invariant_across_counts_pressure_and_depth() {
        let sparse0 = body(1, 1, 0);
        let sparse_fee = required(&sparse0, 0, 24);
        let sparse = body(1, 1, sparse_fee);
        let dense_active = occupancy_threshold(32, PRESSURE_EXTREME_BPS);
        let dense0 = body(8, 2, 0);
        let dense_fee = required(&dense0, dense_active, 32);
        let dense = body(8, 2, dense_fee);
        let sparse_max =
            noid_chain::consensus::emission::block_reward(24) + claimable(&sparse, 0, 24);
        let dense_max =
            noid_chain::consensus::emission::block_reward(32) + claimable(&dense, dense_active, 32);
        let (a, aw, _) = build_case(&[sparse], 0, 24, 24, sparse_max);
        let (c, cw, _) = build_case(&[dense], dense_active, 32, 32, dense_max);
        let ghost = noid_gkr::ghost_tx::ghost_tx_body();
        let (g, gw, gt) = build_case_with_liveness(
            &[ghost],
            &[false],
            dense_active,
            32,
            32,
            noid_chain::consensus::emission::block_reward(32),
        );
        assert!(a.satisfies(&aw));
        assert!(c.satisfies(&cw));
        assert!(g.satisfies(&gw));
        assert_eq!(value(&gw, &gt.groups[0].minimum_fee), 0);
        assert_eq!(value(&gw, &gt.groups[0].burned_fee), 0);
        assert_eq!(value(&gw, &gt.groups[0].claimable_fee), 0);
        assert_eq!(a.useful_rows, c.useful_rows);
        assert_eq!(a.useful_rows, g.useful_rows);
        assert_eq!(a.a_0, c.a_0);
        assert_eq!(a.a_0, g.a_0);
        assert_eq!(a.b_0, c.b_0);
        assert_eq!(a.b_0, g.b_0);
        assert_eq!(a.statement_digest(), c.statement_digest());
        assert_eq!(a.statement_digest(), g.statement_digest());
    }
}

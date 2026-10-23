// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! The block-slot assembly: ONE accepted block's component verification
//! replayed inside a FieldR1cs trace.
//!
//! Trace twin of `block_certificate_backend::
//! verify_accepted_block_batch_components` for a single-block batch: every
//! component killshot runs through its existing slot builder, and the
//! cross-component equalities — which the native path gets for free by
//! deriving every component input from the same block objects — become
//! explicit wire sharing and equality pins:
//!
//! - the accepted-claim transcript's child-header section is pinned
//!   field-for-field to the header-hash killshot statement (the claim
//!   transcript embeds `AcceptedBlockHeaderClaim::from_header(header)`);
//! - the claim's parent-section block id is the header's `prev_block_hash`,
//!   its parent state root / height are the start accumulator's;
//! - the direct ten-lane accumulator transition shares the header block-id,
//!   parent-tip, state/depth/counter and height wires; transaction epoch is
//!   selected by a constrained `height mod 144` relation;
//! - every tx-root Merkle path pins its root to the underlying universal
//!   256-leaf Merkle root `M`, its leaf to coinbase, the optional development
//!   payout, or a complete PagedSpend logical hash, its
//!   direction bits to the
//!   CONSTANT bits of its tx position, and the last real path pins its
//!   right-hand siblings to the canonical zero-subtree digests (the padding
//!   rim the native root reconstruction binds); a domain-separated
//!   `TAG_TXROOT(M, tx_count)` wrapper then pins to the header `tx_root`;
//! - each owner-auth slot pins `(logical_txid, owner)` to the constrained
//!   START..END group and discharges its wallet-PCS obligation;
//! - production exact state derives a fixed-capacity paired local/upper walk
//!   from the sibling-only structural carrier. Slot-sorted action leaves and
//!   all 32 slot bits bind its entries/directions; local and segment chains
//!   end at the parent/grown-parent and child header roots selected by the
//!   header-bound dynamic depth.
//! - page-selected amounts accumulate into one checked group conservation
//!   equation; those same group counts drive minimum fee and deterministic
//!   burn, and the mandatory coinbase is bounded by the scheduled miner
//!   subsidy plus the checked 72-bit claimable-fee aggregate.
//!
//! NOT bound here (audited residue, each correctly scoped to another
//! layer, none a hole in what this file claims):
//! - the parent header's `active_slot_count` / `alloc_counter`: CLOSED —
//!   the accumulator boundary carries both counters as lanes; each block
//!   pins its start counters to the claim's PARENT section and its end
//!   direct boundary to the verified header, and the link chain rule
//!   `start == prev.end` closes the chain. Header PoW/ASERT/MTP fields
//!   (timestamp, miner, nonce, target) are deliberately out of π's
//!   scope — a fresh peer validates its own header chain.
//! - shared-region column algebra must be discharged by the post-commit
//!   sidecar: its relation challenges are sampled only after the outer witness
//!   commitment. The older in-builder A/B/C/D transcript twins are retained
//!   temporarily during that migration, but are not production proof
//!   authority because their columns were not committed before their local
//!   Fiat--Shamir draws.
//!
//! The direct rows in this assembly bind authorization, action routing,
//! exact-state transition, continuity, and checked monetary arithmetic. A
//! production proof additionally requires the post-commit region sidecar to
//! make the shared hashing-column reductions sound.

use noid_core::hardware::flat_to_tower_u128;
use noid_core::Block128;
use noid_poseidon2b::native::compression::compress;
use noid_poseidon2b::native::domain::{capacity_iv, TAG_BLOCKHDR, TAG_SEMHDR, TAG_TXROOT};

use super::trace::accepted_claim_batch::{
    build_direct_accumulator_transition_slot, compress_with_tag_trace, digest_lanes,
    AccumulatorWires, DirectChildWires,
};
use super::trace::action_compaction::{
    bind_mint_packed_values_body_order, compact_action_rows, CompactedActionTrace,
};
use super::trace::action_surface::{
    bind_coinbase_action_with_amount, bind_development_payout_action,
    bind_user_action_surface_for_profile, ActionRowTrace, ActionSurfaceTrace,
};
use super::trace::exact_state::{
    bind_actions_to_exact_state_leaves, bind_exact_state_header_roots_dynamic,
    build_exact_state_structural_region_slot, select_upper_paired_roots, ExactStateSlotWires,
    PairedRootCellPair, StateDepthTrace,
};
use super::trace::fee_arithmetic::bind_block_fee_arithmetic;
use super::trace::paged_spend::{bind_paged_spend_stream, PagedSpendGroupTrace};
use super::trace::public_arithmetic::{bind_user_public_arithmetic, UserPublicArithmeticTrace};
use super::trace::region_source_binding::{
    PairedExactStateCells, SpineContractRegion, SpineInstanceRegion, SpineRegionData,
    TxRootPathRegion, TxRootRegionData,
};
use super::trace::scheduled_allocation::PreparedDevelopmentAllocation;
use super::trace::segment_compaction::{bind_segment_upper_chain, compact_segment_updates};
use super::trace::tx_body_spine::SpineInputsTrace;
use super::trace::zk_authorization_candidate::{
    bind_selected_zk_block_region, PreparedSelectedZkAuthorizations, SelectedZkBlockRegionBinding,
};
use super::trace::{
    alloc_block, const_block, flat_const, flat_of, integer_add_no_overflow, lt_strict_expr, mul,
    pin_eq, pin_lt_strict, pin_zero, poseidon2b_permute, range_check_bits, FieldR1csBuilder,
    LinExpr, Wire, F128,
};
use crate::acceptance::history_step::{
    HistoryStepBlockComponents, V2ContractComponentInput, V2_CONTRACT_SLOTS,
};
use crate::accumulator::ChainAccumulator;
use crate::region_sidecar::{BlockRegionPreparation, BlockRegionSidecarVk, RegionSidecarError};
use noid_chain::block_header::BlockHeader;
use noid_gkr::SpineInputs;
use noid_ivc_core::deep_chain::spine::{
    build_spine_instance_columns_with_contract, SpineContractInstanceFlat, SpineInstanceFlat,
};
use noid_ivc_core::field_circuit::f128_to_u128;

/// A compile-time relation choice made by the owning history protocol. It is
/// not derived from transaction data or supplied by a proof's public inputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::acceptance) enum BlockRelationProfile {
    LegacyV1,
    V2,
    ScheduledV2(crate::acceptance::history_step::v2::V2Config),
}

impl BlockRelationProfile {
    fn native_header_capacity(self) -> Option<usize> {
        match self {
            Self::ScheduledV2(config) => config
                .native_header_capacity()
                .filter(|&capacity| capacity > 0),
            _ => None,
        }
    }
    fn native_financial_config(
        self,
    ) -> Option<crate::acceptance::history_step::v2::NativeFinancialConfig> {
        match self {
            Self::ScheduledV2(config) => config.native_financial_config(),
            _ => None,
        }
    }
    fn native_sequential_config(
        self,
    ) -> Option<super::trace::native_assets::sequential_trade::kernel::TradeKernelConfig> {
        match self {
            Self::ScheduledV2(config) => config.native_sequential_config(),
            _ => None,
        }
    }
    fn native_namespace(self) -> bool {
        matches!(self, Self::ScheduledV2(config) if config.native_header_capacity().is_some())
    }
    fn contracts(self) -> bool {
        self != Self::LegacyV1
    }
    fn contract_slots(self) -> usize {
        match self {
            Self::LegacyV1 => 0,
            Self::V2 => V2_CONTRACT_SLOTS,
            Self::ScheduledV2(config) => config.contract_slots(),
        }
    }
    fn geometry(self, tier: usize) -> crate::region_sidecar::SelectedZkBlockGeometry {
        match self {
            Self::ScheduledV2(config) => {
                assert_eq!(config.pages(), tier);
                config.block_geometry()
            }
            Self::LegacyV1 => {
                let mut geometry = crate::region_sidecar::selected_zk_block_geometry(tier)
                    .expect("canonical selected block geometry");
                geometry.authorization_version = noid_tx::OwnerAuthorizationVersion::V3;
                geometry
            }
            Self::V2 => crate::region_sidecar::selected_zk_block_geometry(tier)
                .expect("canonical selected block geometry"),
        }
    }
}

#[cfg(test)]
mod selected_zk_capability_tests {
    use super::*;
    use noid_core::TowerField;

    #[test]
    fn object_spine_prefix_is_independent_of_the_system_record() {
        use crate::acceptance::history_step::v2::V2Config;
        use noid_chain::consensus::forks::{ForkSchedule, V2Activation};
        use noid_poseidon2b::primitives::Address;
        use noid_tx::experimental_object::{transaction_contexts, ObjectOpening};
        for (pages, capacity) in [(25, 16), (64, 32), (64, 64)] {
            let config = V2Config::with_limits(
                23,
                pages,
                pages * 8,
                capacity,
                ForkSchedule::new(Some(5), V2Activation::new(10, 30)).unwrap(),
            )
            .unwrap();
            let mut digest = None;
            for requested in [0usize, 1, 4, capacity] {
                for system_record in [false, true] {
                    let count = requested.min(pages - usize::from(system_record));
                    let user_base = 1 + usize::from(system_record);
                    let mut bodies = vec![noid_gkr::ghost_tx::ghost_tx_body(); pages + 1];
                    let mut contracts = Vec::new();
                    for slot in 0..count {
                        let opening = ObjectOpening {
                            program: noid_tx::experimental_object::integer_program::EMPTY_PROGRAM,
                            state: Block128::from(slot as u128 + 1),
                            claim_authority: Address([1; 32]),
                            recovery_authority: Address([2; 32]),
                            deadline: 100,
                            claim_recipient: Address([3; 32]),
                            recovery_recipient: Address([4; 32]),
                            rules: noid_tx::experimental_object::ObjectRules {
                                max_fee: u64::MAX,
                                min_retained: 0,
                                max_payout: u64::MAX,
                                modes: 31,
                            },
                        };
                        let body = &mut bodies[user_base + slot];
                        body.input_owner = opening.root();
                        body.outputs[0].owner = opening.root();
                        contracts.push(V2ContractComponentInput {
                            body_index: user_base + slot,
                            live: true,
                            program: opening.program,
                            current: opening.state,
                            contexts: transaction_contexts(body),
                            next: opening.state,
                            controller: opening.claim_authority.as_fields(),
                            refund_authority: opening.recovery_authority.as_fields(),
                            terminal: false,
                            deadline: opening.deadline,
                            claim_recipient: opening.claim_recipient.as_fields(),
                            refund_recipient: opening.recovery_recipient.as_fields(),
                            rules: opening.rules,
                        });
                    }
                    let natives = bodies
                        .iter()
                        .map(noid_gkr::spine_statement::spine_inputs_from_body)
                        .collect::<Vec<_>>();
                    // This component test binds the supplied body/commitment aliases;
                    // the complete direct relation separately checks body hashing.
                    let hashes = vec![[Block128::ZERO; 2]; natives.len()];
                    let mut b = FieldR1csBuilder::new();
                    let prefix_wire = b.alloc_bool(system_record);
                    let prefix = LinExpr::from_wire(prefix_wire);
                    let inputs = natives
                        .iter()
                        .map(|n| SpineInputsTrace::alloc(&mut b, n))
                        .collect::<Vec<_>>();
                    let hash_wires = hashes
                        .iter()
                        .map(|pair| pair.map(|value| alloc_block(&mut b, value)))
                        .collect::<Vec<_>>();
                    let raw = spine_region_data_from_wires(
                        &mut b,
                        &natives,
                        &hashes,
                        &inputs,
                        &hash_wires,
                        &contracts,
                        user_base,
                        BlockRelationProfile::ScheduledV2(config),
                    );
                    assert!(raw.instances[0].contract.is_none());
                    assert!(raw.instances[1..=(capacity + 1).min(pages)]
                        .iter()
                        .all(|s| s.contract.is_some()));
                    let views = select_v2_contract_views(&mut b, &raw, &prefix, capacity);
                    assert_eq!(views.len(), capacity);
                    for (slot, view) in views.iter().enumerate() {
                        assert_eq!(
                            view.live.eval(b.values()),
                            if slot < count { F128::ONE } else { F128::ZERO }
                        );
                        assert_eq!(
                            view.current_w.eval(b.values()),
                            flat_of(Block128::from(if slot < count {
                                slot as u128 + 1
                            } else {
                                0
                            }))
                        );
                        // Pin to independently allocated claimed user states so a
                        // substituted schedule bit cannot merely select another view.
                        let expected = alloc_block(
                            &mut b,
                            Block128::from(if slot < count { slot as u128 + 1 } else { 0 }),
                        );
                        pin_eq(&mut b, &view.current_w, &expected);
                    }
                    let (matrix, witness) = b.build();
                    assert!(matrix.satisfies(&witness));
                    let actual = matrix.structural_statement_digest();
                    assert!(
                        digest.is_none_or(|expected| expected == actual),
                        "count={count}, system={system_record}"
                    );
                    digest = Some(actual);
                    if count != 0 {
                        let mut forged = witness;
                        forged[prefix_wire.0 as usize] += F128::ONE;
                        assert!(!matrix.satisfies(&forged));
                    }
                }
            }
        }
    }

    fn zero_action_row() -> ActionRowTrace {
        ActionRowTrace {
            live: LinExpr::zero(),
            slot_index: LinExpr::zero(),
            value: LinExpr::zero(),
            owner: [LinExpr::zero(), LinExpr::zero()],
            is_mint: LinExpr::zero(),
        }
    }

    fn authorization_surface(contract: bool) -> ActionSurfaceTrace {
        ActionSurfaceTrace {
            tx_live: LinExpr::constant(F128::ONE),
            raw_inputs: std::array::from_fn(|_| LinExpr::zero()),
            raw_outputs: std::array::from_fn(|_| LinExpr::zero()),
            start: LinExpr::zero(),
            end: LinExpr::zero(),
            contract: LinExpr::constant(if contract { F128::ONE } else { F128::ZERO }),
            terminal: LinExpr::zero(),
            native: LinExpr::zero(),
            native_header: LinExpr::zero(),
            selected_inputs: std::array::from_fn(|_| LinExpr::zero()),
            selected_outputs: std::array::from_fn(|_| LinExpr::zero()),
            input_rows: std::array::from_fn(|_| zero_action_row()),
            output_rows: std::array::from_fn(|_| zero_action_row()),
        }
    }

    #[test]
    fn v2_b255_preserves_all_255_authorization_positions() {
        for contract_count in [0usize, V2_CONTRACT_SLOTS] {
            let mut b = FieldR1csBuilder::new();
            let groups = (0..256)
                .map(|index| PagedSpendGroupTrace {
                    live: LinExpr::constant(if index < 255 { F128::ONE } else { F128::ZERO }),
                    logical_txid: [
                        const_block(Block128::from(index as u128 + 1)),
                        const_block(Block128::from(index as u128 + 257)),
                    ],
                    input_owner: [
                        const_block(Block128::from(index as u128 + 513)),
                        const_block(Block128::from(index as u128 + 769)),
                    ],
                    fee: LinExpr::zero(),
                    live_input_count: LinExpr::zero(),
                    live_output_count: LinExpr::zero(),
                    end_page: LinExpr::zero(),
                })
                .collect::<Vec<_>>();
            let surfaces = (0..255)
                .map(|index| authorization_surface(index < contract_count))
                .collect::<Vec<_>>();
            let policy = V2ContractPolicy {
                height: LinExpr::zero(),
                expected_authorities: (0..V2_CONTRACT_SLOTS)
                    .map(|index| {
                        [
                            const_block(Block128::from(index as u128 + 1025)),
                            const_block(Block128::from(index as u128 + 1281)),
                        ]
                    })
                    .collect(),
                before_deadlines: vec![LinExpr::zero(); V2_CONTRACT_SLOTS],
            };
            let capability =
                mint_v2_selected_zk_authorization_capability(&mut b, &groups, &surfaces, &policy);
            assert_eq!(capability.len(), 256);
            assert_eq!(capability.live_count(), 255);
            for index in 0..255 {
                let slot = capability.slot(index);
                assert_eq!(slot.kind(), CanonicalSelectedZkAuthorizationSlotKind::Live);
                assert_eq!(slot.live_entry_index, Some(index));
                let expected = if index < contract_count {
                    [
                        Block128::from(index as u128 + 1025),
                        Block128::from(index as u128 + 1281),
                    ]
                } else {
                    [
                        Block128::from(index as u128 + 513),
                        Block128::from(index as u128 + 769),
                    ]
                };
                assert_eq!(slot.native_statement().address, expected);
            }
            assert_eq!(
                capability.slot(255).kind(),
                CanonicalSelectedZkAuthorizationSlotKind::Pad
            );
        }
    }

    #[test]
    fn b255_capability_is_zero_row_exact_and_pad_is_constant_metadata() {
        let ghost_body = noid_gkr::ghost_tx::ghost_tx_body();
        let ghost_statement = noid_gkr::zk_authorization::ZkAuthCapsuleOwnerStatement {
            tx_body_hash: noid_gkr::ghost_tx::ghost_tx_body_hash(),
            address: ghost_body.input_owner.as_fields(),
        };
        for live_count in [0usize, 1, 17, 254, 255] {
            let (b, capability) = canonical_selected_zk_authorization_fixture(live_count);
            assert_eq!(capability.len(), 256);
            assert_eq!(capability.live_count(), live_count);
            for index in 0..255 {
                let slot = capability.slot(index);
                assert!(slot.body_aliases().is_some());
                assert_eq!(
                    slot.kind(),
                    if index < live_count {
                        CanonicalSelectedZkAuthorizationSlotKind::Live
                    } else {
                        CanonicalSelectedZkAuthorizationSlotKind::Ghost
                    }
                );
                assert_eq!(
                    slot.liveness().eval(b.values()),
                    if index < live_count {
                        F128::ONE
                    } else {
                        F128::ZERO
                    }
                );
            }
            let pad = capability.slot(255);
            assert_eq!(pad.kind(), CanonicalSelectedZkAuthorizationSlotKind::Pad);
            assert!(pad.body_aliases().is_none());
            assert_eq!(pad.liveness().eval(b.values()), F128::ZERO);
            assert_eq!(pad.native_statement(), ghost_statement);
        }
    }

    #[test]
    fn selected_capability_uses_each_canonical_class_capacity() {
        for tier in [25usize, 255] {
            let geometry = crate::region_sidecar::selected_zk_block_geometry(tier).unwrap();
            for live_count in [0usize, tier] {
                let (b, capability) =
                    canonical_selected_zk_authorization_fixture_for_tier(tier, live_count);
                assert_eq!(capability.len(), geometry.auth_tiles);
                assert_eq!(capability.live_count(), live_count);
                for index in 0..tier {
                    assert!(capability.slot(index).body_aliases().is_some());
                    assert_eq!(
                        capability.slot(index).liveness().eval(b.values()),
                        if index < live_count {
                            F128::ONE
                        } else {
                            F128::ZERO
                        }
                    );
                }
                for index in tier..geometry.auth_tiles {
                    assert_eq!(
                        capability.slot(index).kind(),
                        CanonicalSelectedZkAuthorizationSlotKind::Pad
                    );
                    assert!(capability.slot(index).body_aliases().is_none());
                }
            }
        }
    }

    #[test]
    fn capability_carrier_has_no_clone_or_raw_constructor_surface() {
        let source = include_str!("block_slots.rs");
        let capability_name = ["CanonicalSelectedZkAuthorization", "Capability"].concat();
        let declaration_marker = format!("struct {capability_name}");
        let declaration = source
            .split(&declaration_marker)
            .nth(1)
            .expect("capability declaration");
        let header = declaration.split('}').next().expect("capability header");
        assert!(!header.contains("pub "), "capability field became public");
        assert!(!source.contains(&format!("impl Clone for {capability_name}")));
        let raw_constructor =
            ["fn new_canonical_selected_zk_", "authorization_capability"].concat();
        assert!(!source.contains(&raw_constructor));
        let free_take = ["fn take_selected_zk_", "authorization_capability"].concat();
        assert!(!source.contains(&free_take));
    }

    #[test]
    fn canonical_builder_has_no_runtime_authorization_backend_and_preserves_column_order() {
        let source = include_str!("block_slots.rs");
        let backend_type = ["BlockAuthorization", "Backend"].concat();
        let configurable_builder = ["build_block_slots", "_with_config"].concat();
        assert!(!source.contains(&backend_type));
        assert!(!source.contains(&configurable_builder));
        let core = source
            .rsplit("fn build_selected_zk_block_slots_core")
            .next()
            .expect("canonical private authorization core");

        let fee = core
            .find("bind_block_fee_arithmetic")
            .expect("common fee arithmetic");
        let selected_region = core
            .find("let selected_region = Some(bind_selected_zk_block_region")
            .expect("selected region bridge");
        assert!(
            fee < selected_region,
            "selected columns moved before the frozen fee-row prefix"
        );
        assert_eq!(
            core.matches("mint_v2_selected_zk_authorization_capability")
                .count(),
            1,
            "selected capability must be minted once inside the canonical core"
        );
    }
}

/// Offsets inside the 15-field semantic header schedule — the PoW schedule
/// (`pow_header_fields_into` order) with the nonce removed. The relation is
/// nonce-free: the chain link over the exact nonce stays native, and the
/// child step's parent-seal replay derives the parent block id in-circuit.
pub mod header_fields {
    pub const PREV_BLOCK_HASH: usize = 0; // 2 lanes
    pub const STATE_ROOT: usize = 2; // 2
    pub const TX_ROOT: usize = 4; // 2
    pub const TIMESTAMP: usize = 6;
    pub const HEIGHT: usize = 7;
    pub const MINER: usize = 8; // 2
    pub const TARGET: usize = 10; // 2
    pub const LOG_SLOTS: usize = 12;
    pub const ACTIVE_SLOT_COUNT: usize = 13;
    pub const ALLOC_COUNTER: usize = 14;
    pub const FIELDS: usize = 15;
}

const _: () =
    assert!(header_fields::FIELDS + 1 == noid_chain::consensus::pow::POW_HEADER_FIELD_COUNT);

/// Class-independent nonce-free suffix: direct accumulator transition plus
/// the exact semantic `SEMHDR` replay. Every row is known at template time.
const DIRECT_BLOCK_TAIL_ROWS: usize = 4_042;

fn pin_eq2(b: &mut FieldR1csBuilder, a: &[LinExpr; 2], c: &[LinExpr; 2]) {
    pin_eq(b, &a[0], &c[0]);
    pin_eq(b, &a[1], &c[1]);
}

/// Boolean select over the characteristic-two field:
/// `when_zero + selector * (when_one + when_zero)`.
fn select_expr(
    b: &mut FieldR1csBuilder,
    selector: &LinExpr,
    when_one: &LinExpr,
    when_zero: &LinExpr,
) -> LinExpr {
    when_zero.add(&mul(b, selector, &when_one.add(when_zero)))
}

fn constant_spine_inputs_trace(native: &SpineInputs) -> SpineInputsTrace {
    SpineInputsTrace {
        leaves: std::array::from_fn(|leaf| {
            std::array::from_fn(|lane| const_block(native.leaves[leaf][lane]))
        }),
    }
}

fn select_spine_inputs_trace(
    b: &mut FieldR1csBuilder,
    selector: &LinExpr,
    when_one: &SpineInputsTrace,
    when_zero: &SpineInputsTrace,
) -> SpineInputsTrace {
    SpineInputsTrace {
        leaves: std::array::from_fn(|leaf| {
            std::array::from_fn(|lane| {
                select_expr(
                    b,
                    selector,
                    &when_one.leaves[leaf][lane],
                    &when_zero.leaves[leaf][lane],
                )
            })
        }),
    }
}

/// Pin `child == parent + 1` as u64 INTEGERS (not field/XOR): a
/// ripple-carry increment over the tower-bit decomposition of `parent`.
/// In char 2 the field ops ARE the bit ops — `bit_i XOR carry_i` is
/// `+`, `bit_i AND carry_i` is `*` — so the incrementer is exact and the
/// no-overflow guard pins the final carry to zero.
fn pin_u64_successor(b: &mut FieldR1csBuilder, parent: &LinExpr, child: &LinExpr) {
    const N: usize = 64;
    let parent_bits = range_check_bits(b, parent, N);
    let mut carry = LinExpr::constant(F128::ONE);
    let mut recon = LinExpr::zero();
    let mut terms: Vec<LinExpr> = Vec::with_capacity(N);
    for (i, &bit) in parent_bits.iter().enumerate() {
        let p_i = LinExpr::from_wire(bit);
        // child_i = p_i XOR carry_i.
        let child_i = p_i.add(&carry);
        terms.push(child_i.scale(flat_const(1u128 << i)));
        // carry_{i+1} = p_i AND carry_i.
        carry = mul(b, &p_i, &carry);
    }
    // Assemble the reconstruction once (avoid the quadratic add loop).
    for t in &terms {
        recon = recon.add(t);
    }
    // No u64 overflow: the successor stays in range.
    pin_zero(b, &carry);
    pin_eq(b, child, &recon);
}

/// Prove `parent + mints = child + spends` over unsigned u64 integers.
/// Both sides reject overflow; the scalar inputs are range-checked by the
/// adders rather than interpreted as characteristic-two XOR sums.
fn bind_active_slot_counter_delta(
    b: &mut FieldR1csBuilder,
    parent: &LinExpr,
    child: &LinExpr,
    spends: &LinExpr,
    mints: &LinExpr,
) {
    let parent_plus_mints = integer_add_no_overflow(b, parent, mints, 64);
    let child_plus_spends = integer_add_no_overflow(b, child, spends, 64);
    pin_eq(b, &parent_plus_mints, &child_plus_spends);
}

/// Close the production exact-state relation from the slot-sorted action
/// prefix through the paired local/upper Merkle walks to the header-bound
/// old/new roots.
fn bind_paired_exact_state_transition(
    b: &mut FieldR1csBuilder,
    actions: &CompactedActionTrace,
    exact_state: &ExactStateSlotWires,
    paired: &PairedExactStateCells,
    child_depth: &StateDepthTrace,
) {
    let touched_capacity = actions.rows.len();
    assert_eq!(exact_state.slot_leaves.len(), 2 * touched_capacity);
    assert_eq!(paired.local.len(), touched_capacity);
    assert!(!paired.upper.is_empty());
    assert!(paired.upper.len() <= touched_capacity);

    let (old_leaves, new_leaves) = exact_state.slot_leaves.split_at(touched_capacity);
    bind_actions_to_exact_state_leaves(b, &actions.rows, old_leaves, new_leaves);

    let mut local_before = Vec::with_capacity(touched_capacity);
    let mut local_after = Vec::with_capacity(touched_capacity);
    for index in 0..touched_capacity {
        let cells = &paired.local[index];
        pin_eq2(b, &old_leaves[index].expected_leaf, &cells.old_entry);
        pin_eq2(b, &new_leaves[index].expected_leaf, &cells.new_entry);
        for level in 0..16 {
            pin_eq(
                b,
                &cells.directions[level],
                &LinExpr::from_wire(actions.slot_bits[index][level]),
            );
        }
        local_before.push(cells.old_root.clone());
        local_after.push(cells.new_root.clone());
    }

    let segments = compact_segment_updates(
        b,
        &actions.rows,
        &actions.slot_bits,
        &actions.adjacent_msb_one_hot,
        &actions.adjacent_both_live,
        &local_before,
        &local_after,
        paired.upper.len(),
    );

    let mut upper_old_entries = Vec::with_capacity(paired.upper.len());
    let mut upper_new_entries = Vec::with_capacity(paired.upper.len());
    let mut upper_before = Vec::with_capacity(paired.upper.len());
    let mut upper_after = Vec::with_capacity(paired.upper.len());
    for (index, cells) in paired.upper.iter().enumerate() {
        for level in 0..16 {
            pin_eq(
                b,
                &cells.directions[level],
                &LinExpr::from_wire(segments.segment_id_bits[index][level]),
            );
        }
        let roots_by_depth: [PairedRootCellPair; 16] = std::array::from_fn(|level| {
            [
                cells.old_roots[level].clone(),
                cells.new_roots[level].clone(),
            ]
        });
        let selected = select_upper_paired_roots(b, child_depth, &roots_by_depth);
        upper_old_entries.push(cells.old_entry.clone());
        upper_new_entries.push(cells.new_entry.clone());
        upper_before.push(selected[0].clone());
        upper_after.push(selected[1].clone());
    }

    bind_segment_upper_chain(
        b,
        &segments,
        &upper_old_entries,
        &upper_new_entries,
        &upper_before,
        &upper_after,
        &exact_state.roots.old_root,
        &exact_state.roots.new_root,
    );
}

/// `Σ terms` as an INTEGER. A single term is returned unchanged (no adder wires),
/// so a single-tx block reproduces the former single-count path exactly; K terms
/// cost K−1 ripple-carry adds. 16 bits hold any block total (≤ 255·255 < 2^16).
fn pin_u64_sum(b: &mut FieldR1csBuilder, terms: &[LinExpr]) -> LinExpr {
    const N: usize = 16;
    match terms.split_first() {
        None => LinExpr::zero(),
        Some((first, rest)) => {
            let mut acc = first.clone();
            for t in rest {
                acc = integer_add_no_overflow(b, &acc, t, N);
            }
            acc
        }
    }
}

fn append_page_action_surface(
    b: &mut FieldR1csBuilder,
    spine: &SpineInputsTrace,
    page_live: &LinExpr,
    candidates: &mut Vec<ActionRowTrace>,
    input_selectors: &mut Vec<LinExpr>,
    output_selectors: &mut Vec<LinExpr>,
    profile: BlockRelationProfile,
) -> (ActionSurfaceTrace, UserPublicArithmeticTrace) {
    let surface = if profile.native_header_capacity().is_some() {
        super::trace::action_surface::bind_user_action_surface_v2_1(b, spine, page_live)
    } else {
        bind_user_action_surface_for_profile(b, spine, page_live, profile.contracts())
    };
    let arithmetic = if profile.native_header_capacity().is_some() {
        super::trace::public_arithmetic::bind_user_public_arithmetic_v2_1(b, spine, &surface)
    } else {
        bind_user_public_arithmetic(b, spine, &surface)
    };
    input_selectors.extend(surface.selected_inputs.iter().cloned());
    output_selectors.extend(surface.selected_outputs.iter().cloned());
    candidates.extend(surface.ordered_rows());
    (surface, arithmetic)
}

/// Bind the research-v2 body discriminator to the fixed contract-capable
/// prefix. The loop bounds and row schedule are independent of how many calls
/// are live, so ordinary-only and envelope-saturating blocks share one matrix.
fn bind_v2_contract_partition(
    b: &mut FieldR1csBuilder,
    surfaces: &[ActionSurfaceTrace],
    contracts: &[V2ContractView],
    require_prefix: bool,
) {
    assert!(surfaces.len() >= contracts.len());

    let mut previous_contract: Option<LinExpr> = None;
    for (slot, surface) in surfaces.iter().enumerate() {
        if slot < contracts.len() {
            let contract = &contracts[slot];
            pin_eq(b, &surface.contract, &contract.live);
            pin_eq(b, &surface.terminal, &contract.terminal);

            // Contract calls are one-page logical transactions over exactly
            // one consumed object. Continuing calls must create output zero;
            // terminal calls also create output zero, but it is the selected
            // recipient rather than a successor object. Output one remains
            // available for a public side effect on continuing calls.
            let required = [
                &surface.start,
                &surface.end,
                &surface.raw_inputs[0],
                &surface.raw_outputs[0],
            ];
            for bit in required {
                let violation = mul(b, &surface.contract, &bit.add_const(F128::ONE));
                pin_zero(b, &violation);
            }
            for input in &surface.raw_inputs[1..] {
                let violation = mul(b, &surface.contract, input);
                pin_zero(b, &violation);
            }
            let terminal_side_effect = mul(b, &surface.terminal, &surface.raw_outputs[1]);
            pin_zero(b, &terminal_side_effect);

            if require_prefix {
                if let Some(previous) = previous_contract.as_ref() {
                    let gap = mul(b, &surface.contract, &previous.add_const(F128::ONE));
                    pin_zero(b, &gap);
                }
            }
            previous_contract = Some(surface.contract.clone());
        } else {
            pin_zero(b, &surface.contract);
            pin_zero(b, &surface.terminal);
        }
    }
}

/// User-slot views of the fixed raw spine prefix. The schedule selects whether
/// a system record precedes the users, without moving any Meta-A binding.
struct V2ContractView {
    live: LinExpr,
    terminal: LinExpr,
    program_w: [[LinExpr; 2]; noid_tx::experimental_object::PROGRAM_STEPS],
    current_w: LinExpr,
    next_w: LinExpr,
    controller_w: [LinExpr; 2],
    refund_authority_w: [LinExpr; 2],
    contexts_w: [LinExpr; 8],
    deadline_w: LinExpr,
    claim_recipient_w: [LinExpr; 2],
    refund_recipient_w: [LinExpr; 2],
    rules_w: [LinExpr; 4],
}

fn select_v2_contract_views(
    b: &mut FieldR1csBuilder,
    spine: &SpineRegionData,
    system_prefix: &LinExpr,
    contract_slots: usize,
) -> Vec<V2ContractView> {
    let raw: Vec<&SpineContractRegion> = spine
        .instances
        .iter()
        .skip(1)
        .take(contract_slots + 1)
        .map(|instance| instance.contract.as_ref().expect("fixed raw object prefix"))
        .collect();
    assert!(contract_slots > 0 && raw.len() >= contract_slots);
    let first_unused = mul(b, system_prefix, &raw[0].live);
    pin_zero(b, &first_unused);
    if let Some(last) = raw.get(contract_slots) {
        let last_unused = mul(b, &system_prefix.add_const(F128::ONE), &last.live);
        pin_zero(b, &last_unused);
    }
    // With a fully contract-capable block, the shifted final user position
    // has no physical body tile. Its view is a constant ghost; the common
    // payout-over-capacity constraint already requires that user to be dead.
    (0..contract_slots)
        .map(|slot| {
            let (lo, hi) = (raw[slot], raw.get(slot + 1).copied());
            let zero = LinExpr::zero();
            let mut select = |one: Option<&LinExpr>, other: &LinExpr| {
                select_expr(b, system_prefix, one.unwrap_or(&zero), other)
            };
            V2ContractView {
                live: select(hi.map(|v| &v.live), &lo.live),
                terminal: select(hi.map(|v| &v.terminal), &lo.terminal),
                program_w: std::array::from_fn(|step| {
                    std::array::from_fn(|lane| {
                        select(
                            hi.map(|v| &v.program_w[step][lane]),
                            &lo.program_w[step][lane],
                        )
                    })
                }),
                current_w: select(hi.map(|v| &v.current_w), &lo.current_w),
                next_w: select(hi.map(|v| &v.next_w), &lo.next_w),
                controller_w: std::array::from_fn(|lane| {
                    select(hi.map(|v| &v.controller_w[lane]), &lo.controller_w[lane])
                }),
                refund_authority_w: std::array::from_fn(|lane| {
                    select(
                        hi.map(|v| &v.refund_authority_w[lane]),
                        &lo.refund_authority_w[lane],
                    )
                }),
                contexts_w: std::array::from_fn(|step| {
                    select(hi.map(|v| &v.contexts_w[step]), &lo.contexts_w[step])
                }),
                deadline_w: select(hi.map(|v| &v.deadline_w), &lo.deadline_w),
                claim_recipient_w: std::array::from_fn(|lane| {
                    select(
                        hi.map(|v| &v.claim_recipient_w[lane]),
                        &lo.claim_recipient_w[lane],
                    )
                }),
                refund_recipient_w: std::array::from_fn(|lane| {
                    select(
                        hi.map(|v| &v.refund_recipient_w[lane]),
                        &lo.refund_recipient_w[lane],
                    )
                }),
                rules_w: std::array::from_fn(|lane| {
                    select(hi.map(|v| &v.rules_w[lane]), &lo.rules_w[lane])
                }),
            }
        })
        .collect()
}

/// Deadline branch and expected authorization address for each reserved v2
/// contract tile. Program execution is deliberately bound after the large
/// selected-region allocation; only these values are needed to form its
/// authorization statements.
struct V2ContractPolicy {
    height: LinExpr,
    expected_authorities: Vec<[LinExpr; 2]>,
    before_deadlines: Vec<LinExpr>,
}

fn bind_v2_contract_policy(
    b: &mut FieldR1csBuilder,
    contracts: &[V2ContractView],
    height_bits: &[Wire; 64],
) -> V2ContractPolicy {
    let mut expected_authorities = Vec::with_capacity(contracts.len());
    let mut before_deadlines = Vec::with_capacity(contracts.len());
    for contract in contracts {
        let deadline_bits = range_check_bits(b, &contract.deadline_w, 64);
        let before_deadline = lt_strict_expr(b, height_bits, &deadline_bits);
        expected_authorities.push(std::array::from_fn(|lane| {
            select_expr(
                b,
                &before_deadline,
                &contract.controller_w[lane],
                &contract.refund_authority_w[lane],
            )
        }));
        before_deadlines.push(before_deadline);
    }
    V2ContractPolicy {
        height: height_bits
            .iter()
            .enumerate()
            .fold(LinExpr::zero(), |sum, (index, &wire)| {
                sum.add(&LinExpr::from_wire(wire).scale(flat_const(1u128 << index)))
            }),
        expected_authorities,
        before_deadlines,
    }
}

/// Split one committed 128-bit body field into its two unsigned u64 words.
fn v2_integer_words(b: &mut FieldR1csBuilder, value: &LinExpr) -> [LinExpr; 2] {
    let bits = range_check_bits(b, value, 128);
    std::array::from_fn(|word| {
        bits[word * 64..word * 64 + 64].iter().enumerate().fold(
            LinExpr::zero(),
            |sum, (index, &wire)| {
                sum.add(&LinExpr::from_wire(wire).scale(flat_const(1u128 << index)))
            },
        )
    })
}

/// Enforce the bounded integer program, context binding and terminal recipient
/// for every reserved slot. Every row is present even when the slot carries
/// an ordinary wallet transaction, preserving one content-independent matrix.
fn bind_v2_contract_execution(
    b: &mut FieldR1csBuilder,
    page_spines: &[SpineInputsTrace],
    surfaces: &[ActionSurfaceTrace],
    contracts: &[V2ContractView],
    policy: &V2ContractPolicy,
    compact_arithmetic: bool,
) {
    const CONTEXT_SOURCES: [(usize, usize); 8] = [
        (noid_tx::body_hash::TX8X2_LEAF_EPOCH_ANCHOR, 0),
        (noid_tx::body_hash::TX8X2_LEAF_EPOCH_ANCHOR, 1),
        (noid_tx::body_hash::TX8X2_LEAF_FEE, 0),
        (noid_tx::body_hash::TX8X2_LEAF_OUTPUT0_DATA, 1),
        (noid_tx::body_hash::TX8X2_LEAF_OUTPUT1_DATA, 1),
        (noid_tx::body_hash::TX8X2_LEAF_OUTPUT1_OWNER, 0),
        (noid_tx::body_hash::TX8X2_LEAF_OUTPUT1_OWNER, 1),
        (noid_tx::body_hash::TX8X2_LEAF_FLAGS, 0),
    ];
    assert!(page_spines.len() >= contracts.len());
    assert!(surfaces.len() >= contracts.len());
    assert_eq!(policy.before_deadlines.len(), contracts.len());

    for slot in 0..contracts.len() {
        let slot_start = b.num_wires();
        let surface = &surfaces[slot];
        let contract = &contracts[slot];
        let live = &surface.contract;

        for (step, (leaf, lane)) in CONTEXT_SOURCES.into_iter().enumerate() {
            let difference = contract.contexts_w[step].add(&page_spines[slot].leaves[leaf][lane]);
            let gated = mul(b, live, &difference);
            pin_zero(b, &gated);
        }
        let after_context = b.num_wires();

        use noid_tx::body_hash::*;
        let leaves = &page_spines[slot].leaves;
        let input = v2_integer_words(b, &leaves[TX8X2_LEAF_INPUT_BASE][1]);
        let owner0 = v2_integer_words(b, &leaves[TX8X2_LEAF_OUTPUT1_OWNER][0]);
        let owner1 = v2_integer_words(b, &leaves[TX8X2_LEAF_OUTPUT1_OWNER][1]);
        let context = super::trace::integer_program::ContextTrace {
            height: policy.height.clone(),
            fee: leaves[TX8X2_LEAF_FEE][0].clone(),
            payout: leaves[TX8X2_LEAF_OUTPUT1_DATA][1].clone(),
            retained: leaves[TX8X2_LEAF_OUTPUT0_DATA][1].clone(),
            input_amount: input[0].clone(),
            before_deadline: policy.before_deadlines[slot].clone(),
            terminal: surface.terminal.clone(),
            has_payout: surface.raw_outputs[1].clone(),
            payout_owner: [
                owner0[0].clone(),
                owner0[1].clone(),
                owner1[0].clone(),
                owner1[1].clone(),
            ],
            input_creation_id: input[1].clone(),
            input_slot: leaves[TX8X2_LEAF_INPUT_BASE][0].clone(),
            retained_slot: leaves[TX8X2_LEAF_OUTPUT0_DATA][0].clone(),
            payout_slot: leaves[TX8X2_LEAF_OUTPUT1_DATA][0].clone(),
        };
        let bind_program = if compact_arithmetic {
            super::trace::integer_program::bind_program_v2_1
        } else {
            super::trace::integer_program::bind_program
        };
        bind_program(
            b,
            &contract.program_w,
            &contract.current_w,
            &contract.next_w,
            &context,
            live,
        );
        let after_program = b.num_wires();

        let expected_recipient: [LinExpr; 2] = std::array::from_fn(|lane| {
            select_expr(
                b,
                &policy.before_deadlines[slot],
                &contract.claim_recipient_w[lane],
                &contract.refund_recipient_w[lane],
            )
        });
        bind_v2_spending_rules(
            b,
            &page_spines[slot],
            surface,
            contract,
            &policy.before_deadlines[slot],
            &expected_recipient,
        );
        let after_recipient = b.num_wires();
        for lane in 0..2 {
            let output_owner =
                &page_spines[slot].leaves[noid_tx::body_hash::TX8X2_LEAF_OUTPUT0_OWNER][lane];
            let mismatch = output_owner.add(&expected_recipient[lane]);
            let gated = mul(b, &surface.terminal, &mismatch);
            pin_zero(b, &gated);
        }
        if slot == 0 && std::env::var_os("NOID_ROW_LEDGER").is_some() {
            eprintln!(
                "[ledger] v2 execution slot: context={} program={} recipient={} terminal={} total={}",
                after_context - slot_start,
                after_program - after_context,
                after_recipient - after_program,
                b.num_wires() - after_recipient,
                b.num_wires() - slot_start,
            );
        }
    }
}

/// All bounds are committed in the object root and checked as unsigned
/// integers. No witness value changes the row schedule, including mode bits.
fn bind_v2_spending_rules(
    b: &mut FieldR1csBuilder,
    spine: &SpineInputsTrace,
    surface: &ActionSurfaceTrace,
    contract: &V2ContractView,
    before_deadline: &LinExpr,
    recipient: &[LinExpr; 2],
) {
    use noid_tx::body_hash::{
        TX8X2_LEAF_FEE, TX8X2_LEAF_OUTPUT0_DATA, TX8X2_LEAF_OUTPUT1_DATA, TX8X2_LEAF_OUTPUT1_OWNER,
    };
    let max_fee = range_check_bits(b, &contract.rules_w[0], 64);
    let min_retained = range_check_bits(b, &contract.rules_w[1], 64);
    let max_payout = range_check_bits(b, &contract.rules_w[2], 64);
    let modes = range_check_bits(b, &contract.rules_w[3], 5);
    let allow_continue = select_expr(
        b,
        before_deadline,
        &LinExpr::from_wire(modes[0]),
        &LinExpr::from_wire(modes[2]),
    );
    let allow_close = select_expr(
        b,
        before_deadline,
        &LinExpr::from_wire(modes[1]),
        &LinExpr::from_wire(modes[3]),
    );
    // The partition binds terminal => contract and both are boolean.
    let continuing = surface.contract.add(&surface.terminal);
    for (enabled, allowed) in [
        (&continuing, allow_continue),
        (&surface.terminal, allow_close),
    ] {
        let violation = mul(b, enabled, &allowed.add_const(F128::ONE));
        pin_zero(b, &violation);
    }
    let fee = range_check_bits(b, &spine.leaves[TX8X2_LEAF_FEE][0], 64);
    let retained = range_check_bits(b, &spine.leaves[TX8X2_LEAF_OUTPUT0_DATA][1], 64);
    let payout = range_check_bits(b, &spine.leaves[TX8X2_LEAF_OUTPUT1_DATA][1], 64);
    for (enabled, violation) in [
        (&surface.contract, lt_strict_expr(b, &max_fee, &fee)),
        (&continuing, lt_strict_expr(b, &retained, &min_retained)),
        (&continuing, lt_strict_expr(b, &max_payout, &payout)),
    ] {
        let violation = mul(b, enabled, &violation);
        pin_zero(b, &violation);
    }
    let side_output = mul(b, &surface.contract, &surface.raw_outputs[1]);
    let fixed_recipient = mul(
        b,
        &side_output,
        &LinExpr::from_wire(modes[4]).add_const(F128::ONE),
    );
    for lane in 0..2 {
        let mismatch = spine.leaves[TX8X2_LEAF_OUTPUT1_OWNER][lane].add(&recipient[lane]);
        let violation = mul(b, &fixed_recipient, &mismatch);
        pin_zero(b, &violation);
    }
}

/// Bind the universal 256-leaf Merkle root and real transaction count to the
/// header's domain-separated transaction root.
fn bind_tx_root_count_wrapper(
    b: &mut FieldR1csBuilder,
    merkle_root: &[LinExpr; 2],
    tx_count: &LinExpr,
    header_root: &[LinExpr; 2],
) {
    let count_digest = [tx_count.clone(), LinExpr::zero()];
    let wrapped = compress_with_tag_trace(b, TAG_TXROOT, merkle_root, &count_digest);
    pin_eq2(b, &wrapped, header_root);
}

/// The padded tx-tree levels rebuilt from the real tx-body hashes: leaves =
/// the hash digests padded to `2^depth` with the zero digest, then the
/// `compress` ladder — exactly the native `tx_root_merkle_inputs`
/// construction, giving the sibling sets of EVERY leaf (real and padding).
fn padded_tx_tree_levels(hashes: &[[Block128; 2]], depth: usize) -> Vec<Vec<[u8; 32]>> {
    let target = 1usize << depth;
    assert!(hashes.len() <= target, "more txs than tree leaves");
    let mut level: Vec<[u8; 32]> = hashes
        .iter()
        .map(|h| {
            let mut d = [0u8; 32];
            d[..16].copy_from_slice(&h[0].0.to_le_bytes());
            d[16..].copy_from_slice(&h[1].0.to_le_bytes());
            d
        })
        .collect();
    level.resize(target, [0u8; 32]);
    let mut levels = vec![level.clone()];
    while level.len() > 1 {
        level = level
            .chunks_exact(2)
            .map(|p| compress(&p[0], &p[1]))
            .collect();
        levels.push(level.clone());
    }
    levels
}

/// The tier-capacity tx-root handoff: one walk-B path per PADDED-TREE leaf.
/// Leaf `j`'s entry is the live-muxed `live_j · tx_hash_j` (a dead leaf
/// proves the ZERO padding digest), where `live_j` is `1` for the coinbase
/// leaf (when the block carries one), the authorization liveness bit for a
/// user leaf, and `0` for leaves past the capacity. The rim const pins are
/// subsumed: every padding leaf is authenticated as zero directly.
fn tx_root_region_capacity_handoff(
    b: &mut FieldR1csBuilder,
    tx_root_inputs: &[noid_gkr::merkle_circuit::MerklePathInputs],
    real_hashes: &[[Block128; 2]],
    tx_hashes: &[[LinExpr; 2]],
    live_bits: &[LinExpr],
) -> TxRootRegionData {
    let root_native = tx_root_inputs[0].expected_root;
    let root_w = [
        alloc_block(b, root_native[0]),
        alloc_block(b, root_native[1]),
    ];
    tx_root_region_capacity_data_from_wires(
        b,
        tx_root_inputs,
        real_hashes,
        root_w,
        tx_hashes,
        live_bits,
    )
}

/// [`tx_root_region_capacity_handoff`] core on caller-supplied wires (the
/// real build passes the underlying universal-tree root `M` + statement liveness; the scratch
/// mirror passes throwaway allocs of the same natives).
fn tx_root_region_capacity_data_from_wires(
    b: &mut FieldR1csBuilder,
    tx_root_inputs: &[noid_gkr::merkle_circuit::MerklePathInputs],
    real_hashes: &[[Block128; 2]],
    root_w: [LinExpr; 2],
    tx_hashes: &[[LinExpr; 2]],
    live_bits: &[LinExpr],
) -> TxRootRegionData {
    assert!(
        !tx_root_inputs.is_empty(),
        "tx-root region handoff without paths"
    );
    let depth = tx_root_inputs[0].active_depth;
    let n_leaves = 1usize << depth;
    let n_real = real_hashes.len();
    assert!(n_real >= 1 && n_real <= n_leaves);
    assert_eq!(depth, noid_chain::tx_tree::TX_TREE_DEPTH);
    assert!(tx_hashes.len() <= n_leaves);
    assert_eq!(
        tx_hashes.len(),
        live_bits.len(),
        "one logical tx-root liveness selector per hash wire"
    );
    let root_native = tx_root_inputs[0].expected_root;
    let root_flat = [flat_of(root_native[0]), flat_of(root_native[1])];
    for lane in 0..2 {
        assert_eq!(
            root_w[lane].eval(b.values()),
            root_flat[lane],
            "Merkle root wire != the killshot statement root"
        );
    }
    let levels = padded_tx_tree_levels(real_hashes, depth);
    // Cross-check the rebuilt root against the killshot statement.
    assert_eq!(
        digest_lanes(&levels[depth][0]),
        root_native,
        "rebuilt padded tree root"
    );

    let paths: Vec<TxRootPathRegion> = (0..n_leaves)
        .map(|j| {
            // The caller has already compacted the optional system payout
            // into the logical order. Every capacity position therefore has
            // one exact liveness selector; leaves past that capacity are zero.
            let live: LinExpr = if j < live_bits.len() {
                live_bits[j].clone()
            } else {
                LinExpr::zero()
            };
            let entry_w: [LinExpr; 2] = if j < tx_hashes.len() {
                std::array::from_fn(|lane| mul(b, &live, &tx_hashes[j][lane]))
            } else {
                [LinExpr::zero(), LinExpr::zero()]
            };
            let entry_native = digest_lanes(&levels[0][j]);
            let entry_flat = [flat_of(entry_native[0]), flat_of(entry_native[1])];
            for lane in 0..2 {
                assert_eq!(
                    entry_w[lane].eval(b.values()),
                    entry_flat[lane],
                    "live-muxed tx-root entry {j} != the padded-tree leaf"
                );
            }
            let siblings: Vec<[F128; 2]> = (0..depth)
                .map(|l| {
                    let sib = levels[l][(j >> l) ^ 1];
                    let lanes = digest_lanes(&sib);
                    [flat_of(lanes[0]), flat_of(lanes[1])]
                })
                .collect();
            TxRootPathRegion {
                entry_w,
                entry_flat,
                siblings,
            }
        })
        .collect();
    TxRootRegionData {
        depth,
        root_w,
        root_flat,
        paths,
        // No rim constants: every padding leaf is authenticated directly.
        rim_flat: Vec::new(),
    }
}

/// Authorization-slot count of a build: at tier capacity, the capacity
/// rounded up to the next power of two — the walk tiling requires a
/// power-of-two per-slot obligation count, and 255 is the one non-power
/// tier. Slots past the consensus capacity are PAD slots: they prove the
/// same protocol ghost authorization as the in-capacity ghost slots, but no
/// tx slot exists behind them, so their body-hash pin lands on the
/// ghost-body constant and their liveness bit stays zero-valued (the
/// USER_TX_COUNT sum is unchanged). Non-capacity builds keep the caller's
/// tx count (the plural discharge asserts it is a power of two).
#[cfg(test)]
fn tier_auth_slot_count(tier_user_tx_capacity: Option<usize>, n_real_user: usize) -> usize {
    tier_user_tx_capacity.map_or(n_real_user, |tier| {
        super::shape::ShapeClass { tier }.authorization_capacity()
    })
}

/// The same integer count drives State accounting and the explicit candidate
/// input budget. Touched-slot capacity alone is insufficient: a block with
/// fewer outputs could otherwise hide extra spends inside that allocation.
fn bind_block_input_limit(b: &mut FieldR1csBuilder, live_input_sum: &LinExpr, capacity: usize) {
    let count_bits = range_check_bits(b, live_input_sum, 12);
    let cap_plus_one = const_block(Block128::from((capacity + 1) as u128));
    let cap_bits = range_check_bits(b, &cap_plus_one, 12);
    pin_lt_strict(b, &count_bits, &cap_bits);
}

#[cfg(test)]
mod input_budget_tests {
    use super::*;

    #[test]
    fn input_sum_is_bounded_independently_of_output_occupancy() {
        for inputs in [0usize, 96, 384, 385, 768] {
            let mut builder = FieldR1csBuilder::new();
            let selected: Vec<_> = (0..96 * noid_tx::TX_INPUTS)
                .map(|index| alloc_block(&mut builder, Block128::from(u128::from(index < inputs))))
                .collect();
            let sum = pin_u64_sum(&mut builder, &selected);
            bind_block_input_limit(&mut builder, &sum, 384);
            let (matrix, witness) = builder.build();
            assert_eq!(matrix.satisfies(&witness), inputs <= 384, "inputs={inputs}");
        }
    }
}

/// The flat image of one native `SpineInputs` statement (φ lane by lane).
fn spine_instance_flat(n: &SpineInputs) -> SpineInstanceFlat {
    SpineInstanceFlat {
        leaves: std::array::from_fn(|leaf| {
            std::array::from_fn(|lane| flat_of(n.leaves[leaf][lane]))
        }),
    }
}

/// Assemble the tx-body spine region handoff from already-allocated
/// statement wires — the real build passes the spine statement wires + the
/// tx-hash wires; the scratch mirror passes throwaway allocs of the same
/// natives. Every wire is asserted to carry its native flat value at build
/// time (a pure transliteration; the region cell pins do the binding).
fn spine_region_data_from_wires(
    b: &mut FieldR1csBuilder,
    natives: &[SpineInputs],
    native_hashes: &[[Block128; 2]],
    inputs_t: &[SpineInputsTrace],
    tx_hashes: &[[LinExpr; 2]],
    contracts: &[V2ContractComponentInput],
    user_body_base: usize,
    profile: BlockRelationProfile,
) -> SpineRegionData {
    assert_eq!(
        natives.len(),
        inputs_t.len(),
        "one wire set per spine instance"
    );
    assert_eq!(
        natives.len(),
        native_hashes.len(),
        "one hash per spine instance"
    );
    assert_eq!(
        natives.len(),
        tx_hashes.len(),
        "one hash wire pair per instance"
    );
    let assert_pair = |b: &FieldR1csBuilder, w: &[LinExpr; 2], n: &[Block128; 2], what: &str| {
        for lane in 0..2 {
            assert_eq!(
                w[lane].eval(b.values()),
                flat_of(n[lane]),
                "{what} lane {lane}"
            );
        }
    };
    assert!(
        contracts.len() <= profile.contract_slots(),
        "v2 contract prefix overflow"
    );
    for (slot, contract) in contracts.iter().enumerate() {
        assert!(contract.live, "listed v2 contract must be live");
        assert!(
            contract.body_index >= user_body_base
                && contract.body_index - user_body_base < profile.contract_slots(),
            "contract body position exceeds the selected class"
        );
        if slot != 0 {
            assert!(
                contracts[slot - 1].body_index < contract.body_index,
                "contract openings follow strict physical body order"
            );
        }
        if profile.native_sequential_config().is_none() {
            assert_eq!(
                contract.body_index,
                user_body_base + slot,
                "v2 contracts must be a canonical body prefix"
            );
        }
    }
    let instances = natives
        .iter()
        .zip(native_hashes.iter())
        .zip(inputs_t.iter().zip(tx_hashes.iter()))
        .enumerate()
        .map(|(body_index, ((n, h), (t, hw)))| {
            for (leaf, pair) in t.leaves.iter().enumerate() {
                for lane in 0..2 {
                    assert_eq!(
                        pair[lane].eval(b.values()),
                        flat_of(n.leaves[leaf][lane]),
                        "spine raw leaf wire L{leaf}[{lane}]"
                    );
                }
            }
            assert_pair(b, hw, h, "spine tx hash");
            let reserved_slot = body_index
                .checked_sub(1)
                .filter(|slot| profile.contracts() && *slot <= profile.contract_slots());
            let contract = reserved_slot.map(|_| {
                let supplied = contracts
                    .iter()
                    .find(|contract| contract.body_index == body_index);
                let flat = SpineContractInstanceFlat {
                    program: supplied
                        .map(|contract| contract.program)
                        .unwrap_or(noid_tx::experimental_object::integer_program::EMPTY_PROGRAM)
                        .map(|fields| fields.map(flat_of)),
                    current: supplied.map_or(F128::ZERO, |contract| flat_of(contract.current)),
                    next: supplied.map_or(F128::ZERO, |contract| flat_of(contract.next)),
                    controller: supplied
                        .map(|contract| contract.controller.map(flat_of))
                        .unwrap_or([F128::ZERO; 2]),
                    refund_authority: supplied
                        .map(|contract| contract.refund_authority.map(flat_of))
                        .unwrap_or([F128::ZERO; 2]),
                    deadline: supplied.map_or(F128::ZERO, |contract| {
                        flat_of(Block128::from(contract.deadline as u128))
                    }),
                    claim_recipient: supplied
                        .map(|contract| contract.claim_recipient.map(flat_of))
                        .unwrap_or([F128::ZERO; 2]),
                    refund_recipient: supplied
                        .map(|contract| contract.refund_recipient.map(flat_of))
                        .unwrap_or([F128::ZERO; 2]),
                    rules: supplied
                        .map(|contract| contract.rules.fields().map(flat_of))
                        .unwrap_or([F128::ZERO; 4]),
                };
                let built = build_spine_instance_columns_with_contract(
                    &spine_instance_flat(n),
                    Some(&flat),
                );
                let live = supplied.is_some();
                let terminal = supplied.is_some_and(|contract| contract.terminal);
                let live_w = LinExpr::from_wire(b.alloc_bool(live));
                let terminal_w = LinExpr::from_wire(b.alloc_bool(terminal));
                let terminal_without_live = mul(b, &terminal_w, &live_w.add_const(F128::ONE));
                pin_zero(b, &terminal_without_live);
                let program_w = flat
                    .program
                    .map(|fields| fields.map(|value| LinExpr::from_wire(b.alloc_f128(value))));
                let current_w = LinExpr::from_wire(b.alloc_f128(flat.current));
                let next_w = LinExpr::from_wire(b.alloc_f128(flat.next));
                let controller_w = flat
                    .controller
                    .map(|value| LinExpr::from_wire(b.alloc_f128(value)));
                let refund_authority_w = flat
                    .refund_authority
                    .map(|value| LinExpr::from_wire(b.alloc_f128(value)));
                let code_digest_w = built
                    .contract_code_digest
                    .map(|value| LinExpr::from_wire(b.alloc_f128(value)));
                let policy_digest_w = built
                    .contract_policy_digest
                    .map(|value| LinExpr::from_wire(b.alloc_f128(value)));
                let contexts_w = supplied
                    .map(|contract| contract.contexts.map(flat_of))
                    .unwrap_or([F128::ZERO; 8])
                    .map(|value| LinExpr::from_wire(b.alloc_f128(value)));
                let deadline_w = LinExpr::from_wire(b.alloc_f128(flat.deadline));
                let rules_w = flat
                    .rules
                    .map(|value| LinExpr::from_wire(b.alloc_f128(value)));
                let claim_recipient_w = supplied
                    .map(|contract| contract.claim_recipient.map(flat_of))
                    .unwrap_or([F128::ZERO; 2])
                    .map(|value| LinExpr::from_wire(b.alloc_f128(value)));
                let refund_recipient_w = supplied
                    .map(|contract| contract.refund_recipient.map(flat_of))
                    .unwrap_or([F128::ZERO; 2])
                    .map(|value| LinExpr::from_wire(b.alloc_f128(value)));
                let old_object_root_w = built
                    .contract_old_object_root
                    .map(|value| LinExpr::from_wire(b.alloc_f128(value)));
                for lane in 0..2 {
                    let body_old = &t.leaves[noid_tx::body_hash::TX8X2_LEAF_INPUT_OWNER][lane];
                    let gated = mul(b, &live_w, &old_object_root_w[lane].add(body_old));
                    pin_zero(b, &gated);
                }
                let new_object_root_w = built
                    .contract_new_object_root
                    .map(|value| LinExpr::from_wire(b.alloc_f128(value)));
                let continuing = mul(b, &live_w, &terminal_w.add_const(F128::ONE));
                for lane in 0..2 {
                    let body_new = &t.leaves[noid_tx::body_hash::TX8X2_LEAF_OUTPUT0_OWNER][lane];
                    let gated = mul(b, &continuing, &new_object_root_w[lane].add(body_new));
                    pin_zero(b, &gated);
                }
                SpineContractRegion {
                    live: live_w,
                    terminal: terminal_w,
                    flat,
                    program_w,
                    current_w,
                    next_w,
                    controller_w,
                    refund_authority_w,
                    code_digest_w,
                    policy_digest_w,
                    contexts_w,
                    deadline_w,
                    claim_recipient_w,
                    refund_recipient_w,
                    rules_w,
                    old_object_root_w,
                    new_object_root_w,
                }
            });
            SpineInstanceRegion {
                flat: spine_instance_flat(n),
                leaves_w: t.leaves.clone(),
                tx_hash_w: hw.clone(),
                tx_hash_flat: [flat_of(h[0]), flat_of(h[1])],
                contract,
            }
        })
        .collect();
    SpineRegionData {
        instances,
        objects: profile.contracts(),
    }
}

/// Bind the Tx8x2 L0 domain anchor for the coinbase, selected payout view and
/// fixed user-capacity views. Dead user views are complete protocol ghosts.
fn bind_tx_epoch_anchors(
    b: &mut FieldR1csBuilder,
    parent_block_id: &[LinExpr; 2],
    user_anchor: &[LinExpr; 2],
    coinbase: &SpineInputsTrace,
    payout: &SpineInputsTrace,
    user_spines: &[SpineInputsTrace],
    payout_live: &LinExpr,
    user_live_bits: &[LinExpr],
) {
    assert_eq!(user_spines.len(), user_live_bits.len());
    const L0: usize = noid_tx::body_hash::TX8X2_LEAF_EPOCH_ANCHOR;

    for lane in 0..2 {
        pin_eq(b, &coinbase.leaves[L0][lane], &parent_block_id[lane]);
        let difference = payout.leaves[L0][lane].add(&parent_block_id[lane]);
        let gated = mul(b, payout_live, &difference);
        pin_zero(b, &gated);
    }

    let ghost =
        noid_gkr::spine_statement::spine_inputs_from_body(&noid_gkr::ghost_tx::ghost_tx_body());
    for (spine, live) in user_spines.iter().zip(user_live_bits) {
        for lane in 0..2 {
            let epoch_diff = spine.leaves[L0][lane].add(&user_anchor[lane]);
            let gated = mul(b, live, &epoch_diff);
            pin_zero(b, &gated);
        }
        let dead = live.add_const(F128::ONE);
        for leaf in 0..noid_tx::body_hash::BODY_HASH_LEAVES {
            for lane in 0..2 {
                let ghost_diff =
                    spine.leaves[leaf][lane].add(&const_block(ghost.leaves[leaf][lane]));
                let gated = mul(b, &dead, &ghost_diff);
                pin_zero(b, &gated);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Assembly
// ---------------------------------------------------------------------------

/// Canonical role of one selected authorization slot. The role is
/// derived from the already boolean, monotone Block liveness prefix; callers
/// cannot supply or mutate it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::acceptance) enum CanonicalSelectedZkAuthorizationSlotKind {
    Live,
    Ghost,
    Pad,
}

/// One statement/liveness tuple owned by the canonical Block relation.
/// Fields stay private to this module: the selected all-tiles assembly can
/// borrow only the audited views below, never construct a raw statement.
pub(in crate::acceptance) struct CanonicalSelectedZkAuthorizationSlot {
    tx_body_hash: Option<[LinExpr; 2]>,
    expected_address: Option<[LinExpr; 2]>,
    liveness: LinExpr,
    native_statement: noid_gkr::zk_authorization::ZkAuthCapsuleOwnerStatement,
    kind: CanonicalSelectedZkAuthorizationSlotKind,
    /// Index in the native logical-transaction proof vector. The v1 layout
    /// equals the tile index; the research-v2 fixed partition deliberately
    /// does not.
    live_entry_index: Option<usize>,
}

impl CanonicalSelectedZkAuthorizationSlot {
    pub(in crate::acceptance) fn body_aliases(&self) -> Option<(&[LinExpr; 2], &[LinExpr; 2])> {
        self.tx_body_hash
            .as_ref()
            .zip(self.expected_address.as_ref())
    }

    pub(in crate::acceptance) fn liveness(&self) -> &LinExpr {
        &self.liveness
    }

    pub(in crate::acceptance) fn native_statement(
        &self,
    ) -> noid_gkr::zk_authorization::ZkAuthCapsuleOwnerStatement {
        self.native_statement
    }

    pub(in crate::acceptance) fn kind(&self) -> CanonicalSelectedZkAuthorizationSlotKind {
        self.kind
    }

    pub(in crate::acceptance) fn live_entry_index(&self) -> Option<usize> {
        self.live_entry_index
    }
}

/// Non-Clone statement authority minted only by `BlockSlots` after
/// boolean/monotone liveness and complete dead-body and PAD ghost pins are
/// already in the same matrix. It intentionally has no raw constructor or
/// statement-Vec extractor. Builder affinity comes from the private owning
/// selected assembly choke point, not from this carrier by itself.
pub(in crate::acceptance) struct CanonicalSelectedZkAuthorizationCapability {
    slots: Vec<CanonicalSelectedZkAuthorizationSlot>,
}

impl CanonicalSelectedZkAuthorizationCapability {
    pub(in crate::acceptance) fn len(&self) -> usize {
        self.slots.len()
    }

    pub(in crate::acceptance) fn slot(
        &self,
        index: usize,
    ) -> &CanonicalSelectedZkAuthorizationSlot {
        &self.slots[index]
    }

    pub(in crate::acceptance) fn live_count(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| slot.kind == CanonicalSelectedZkAuthorizationSlotKind::Live)
            .count()
    }
}

fn block_from_alias(b: &FieldR1csBuilder, expression: &LinExpr) -> Block128 {
    let flat = f128_to_u128(expression.eval(b.values()));
    Block128::from(flat_to_tower_u128(flat))
}

/// Extract one exact selected-class statement surface. Logical PagedSpend
/// hashes/owners pass through compaction and live/ghost selection expressions,
/// so every body slot is materialized into four canonical one-wire aliases
/// before the transcript checker consumes it. PAD slots have no body; their
/// four protocol constants are materialized later by the selected assembly.
fn mint_canonical_selected_zk_authorization_capability(
    b: &mut FieldR1csBuilder,
    groups: &[PagedSpendGroupTrace],
) -> CanonicalSelectedZkAuthorizationCapability {
    let auth_slots = groups.len();
    let geometry = crate::region_sidecar::selected_zk_block_geometry_for_auth_tiles(auth_slots)
        .expect("selected authorization capacity is canonical");
    let body_auth_slots = geometry.tier;
    assert_eq!(body_auth_slots, geometry.tier);
    assert_eq!(auth_slots, geometry.auth_tiles);
    for group in &groups[body_auth_slots..] {
        assert_eq!(group.live.eval(b.values()), F128::ZERO);
    }

    let ghost_body = noid_gkr::ghost_tx::ghost_tx_body();
    let ghost_hash = noid_gkr::ghost_tx::ghost_tx_body_hash();
    let ghost_address = ghost_body.input_owner.as_fields();
    let ghost_statement = noid_gkr::zk_authorization::ZkAuthCapsuleOwnerStatement {
        tx_body_hash: ghost_hash,
        address: ghost_address,
    };

    let mut slots = Vec::with_capacity(auth_slots);
    for index in 0..body_auth_slots {
        let group = &groups[index];
        let live = group.live.eval(b.values());
        assert!(live == F128::ZERO || live == F128::ONE);
        let kind = if live == F128::ONE {
            CanonicalSelectedZkAuthorizationSlotKind::Live
        } else {
            CanonicalSelectedZkAuthorizationSlotKind::Ghost
        };
        let dead = group.live.add_const(F128::ONE);
        let selected_tx_body_hash = std::array::from_fn(|lane| {
            group.logical_txid[lane].add(&dead.scale(flat_of(ghost_hash[lane])))
        });
        let selected_address = std::array::from_fn(|lane| {
            group.input_owner[lane].add(&dead.scale(flat_of(ghost_address[lane])))
        });
        let tx_body_hash =
            selected_tx_body_hash.map(|expression| LinExpr::from_wire(b.materialize(&expression)));
        let expected_address =
            selected_address.map(|expression| LinExpr::from_wire(b.materialize(&expression)));
        let native_statement = noid_gkr::zk_authorization::ZkAuthCapsuleOwnerStatement {
            tx_body_hash: std::array::from_fn(|lane| block_from_alias(b, &tx_body_hash[lane])),
            address: std::array::from_fn(|lane| block_from_alias(b, &expected_address[lane])),
        };
        if kind == CanonicalSelectedZkAuthorizationSlotKind::Ghost {
            assert_eq!(native_statement, ghost_statement);
        }
        slots.push(CanonicalSelectedZkAuthorizationSlot {
            tx_body_hash: Some(tx_body_hash),
            expected_address: Some(expected_address),
            liveness: group.live.clone(),
            native_statement,
            kind,
            live_entry_index: (kind == CanonicalSelectedZkAuthorizationSlotKind::Live)
                .then_some(index),
        });
    }
    for index in body_auth_slots..auth_slots {
        slots.push(CanonicalSelectedZkAuthorizationSlot {
            tx_body_hash: None,
            expected_address: None,
            liveness: groups[index].live.clone(),
            native_statement: ghost_statement,
            kind: CanonicalSelectedZkAuthorizationSlotKind::Pad,
            live_entry_index: None,
        });
    }
    CanonicalSelectedZkAuthorizationCapability { slots }
}

/// Research-v2 authorization layout shared by B25 and B255. The fixed prefix
/// of ordinary authorization positions is contract-capable rather than being
/// additional positions: a wallet authenticates `input_owner`, while a
/// contract authenticates the deadline-selected authority committed by its
/// object opening. This preserves all 25/255 ordinary transaction positions
/// and one content-independent matrix through the fixed contract envelope.
fn mint_v2_selected_zk_authorization_capability(
    b: &mut FieldR1csBuilder,
    groups: &[PagedSpendGroupTrace],
    surfaces: &[ActionSurfaceTrace],
    policy: &V2ContractPolicy,
) -> CanonicalSelectedZkAuthorizationCapability {
    let auth_slots = groups.len();
    let geometry = crate::region_sidecar::selected_zk_block_geometry_for_auth_tiles(auth_slots)
        .expect("selected authorization capacity is canonical");
    let body_auth_slots = surfaces.len();
    assert!(body_auth_slots < auth_slots);
    assert_eq!(auth_slots, geometry.auth_tiles);
    for group in &groups[body_auth_slots..] {
        assert_eq!(group.live.eval(b.values()), F128::ZERO);
    }

    let ghost_body = noid_gkr::ghost_tx::ghost_tx_body();
    let ghost_hash = noid_gkr::ghost_tx::ghost_tx_body_hash();
    let ghost_address = ghost_body.input_owner.as_fields();
    let ghost_statement = noid_gkr::zk_authorization::ZkAuthCapsuleOwnerStatement {
        tx_body_hash: ghost_hash,
        address: ghost_address,
    };

    let mut slots = Vec::with_capacity(auth_slots);
    for index in 0..body_auth_slots {
        let group = &groups[index];
        let live = group.live.eval(b.values());
        assert!(live == F128::ZERO || live == F128::ONE);
        let kind = if live == F128::ONE {
            CanonicalSelectedZkAuthorizationSlotKind::Live
        } else {
            CanonicalSelectedZkAuthorizationSlotKind::Ghost
        };
        let dead = group.live.add_const(F128::ONE);
        let selected_tx_body_hash = std::array::from_fn(|lane| {
            group.logical_txid[lane].add(&dead.scale(flat_of(ghost_hash[lane])))
        });
        let selected_address = std::array::from_fn(|lane| {
            let authority = if index < policy.expected_authorities.len() {
                select_expr(
                    b,
                    &surfaces[index].contract,
                    &policy.expected_authorities[index][lane],
                    &group.input_owner[lane],
                )
            } else {
                group.input_owner[lane].clone()
            };
            authority.add(&dead.scale(flat_of(ghost_address[lane])))
        });
        let tx_body_hash =
            selected_tx_body_hash.map(|expression| LinExpr::from_wire(b.materialize(&expression)));
        let expected_address =
            selected_address.map(|expression| LinExpr::from_wire(b.materialize(&expression)));
        let native_statement = noid_gkr::zk_authorization::ZkAuthCapsuleOwnerStatement {
            tx_body_hash: std::array::from_fn(|lane| block_from_alias(b, &tx_body_hash[lane])),
            address: std::array::from_fn(|lane| block_from_alias(b, &expected_address[lane])),
        };
        if kind == CanonicalSelectedZkAuthorizationSlotKind::Ghost {
            assert_eq!(native_statement, ghost_statement);
        }
        slots.push(CanonicalSelectedZkAuthorizationSlot {
            tx_body_hash: Some(tx_body_hash),
            expected_address: Some(expected_address),
            liveness: group.live.clone(),
            native_statement,
            kind,
            live_entry_index: (kind == CanonicalSelectedZkAuthorizationSlotKind::Live)
                .then_some(index),
        });
    }
    for index in body_auth_slots..auth_slots {
        slots.push(CanonicalSelectedZkAuthorizationSlot {
            tx_body_hash: None,
            expected_address: None,
            liveness: groups[index].live.clone(),
            native_statement: ghost_statement,
            kind: CanonicalSelectedZkAuthorizationSlotKind::Pad,
            live_entry_index: None,
        });
    }

    assert_eq!(slots.len(), auth_slots);
    CanonicalSelectedZkAuthorizationCapability { slots }
}

#[cfg(test)]
pub(in crate::acceptance) fn canonical_selected_zk_authorization_fixture(
    live_count: usize,
) -> (FieldR1csBuilder, CanonicalSelectedZkAuthorizationCapability) {
    canonical_selected_zk_authorization_fixture_for_tier(255, live_count)
}

#[cfg(test)]
pub(in crate::acceptance) fn canonical_selected_zk_authorization_fixture_for_tier(
    tier: usize,
    live_count: usize,
) -> (FieldR1csBuilder, CanonicalSelectedZkAuthorizationCapability) {
    let geometry = crate::region_sidecar::selected_zk_block_geometry(tier)
        .expect("test fixture tier is canonical");
    let body_auth_slots = geometry.tier;
    assert!(live_count <= body_auth_slots);
    let mut b = FieldR1csBuilder::new();
    let ghost_body = noid_gkr::ghost_tx::ghost_tx_body();
    let ghost_hash = noid_gkr::ghost_tx::ghost_tx_body_hash();
    let ghost_address = ghost_body.input_owner.as_fields();
    let mut groups = (0..body_auth_slots)
        .map(|index| {
            let live = LinExpr::from_wire(b.alloc_bool(index < live_count));
            PagedSpendGroupTrace {
                live: live.clone(),
                logical_txid: ghost_hash.map(|value| {
                    alloc_block(
                        &mut b,
                        if index < live_count {
                            value
                        } else {
                            Block128::from(0u128)
                        },
                    )
                }),
                input_owner: ghost_address.map(|value| {
                    alloc_block(
                        &mut b,
                        if index < live_count {
                            value
                        } else {
                            Block128::from(0u128)
                        },
                    )
                }),
                fee: LinExpr::zero(),
                live_input_count: LinExpr::zero(),
                live_output_count: LinExpr::zero(),
                end_page: LinExpr::zero(),
            }
        })
        .collect::<Vec<_>>();
    for _ in body_auth_slots..geometry.auth_tiles {
        groups.push(PagedSpendGroupTrace {
            live: LinExpr::zero(),
            logical_txid: [LinExpr::zero(), LinExpr::zero()],
            input_owner: [LinExpr::zero(), LinExpr::zero()],
            fee: LinExpr::zero(),
            live_input_count: LinExpr::zero(),
            live_output_count: LinExpr::zero(),
            end_page: LinExpr::zero(),
        });
    }
    let before_mint = b.num_wires();
    let capability = mint_canonical_selected_zk_authorization_capability(&mut b, &groups);
    assert_eq!(
        b.num_wires() - before_mint,
        4 * body_auth_slots,
        "capability mint must materialize four aliases per body slot"
    );
    (b, capability)
}

/// Exact semantic header schedule used by the direct block relation.
///
/// The native PoW/ASERT/MTP path remains consensus authority. `HistoryStep`
/// recomputes the nonce-free `SEMHDR` projection so the recursive terminal
/// binds the complete semantic template; the chain-link id over the exact
/// nonce is checked natively at the tip and sealed in-circuit by the child
/// step's parent-seal replay.
pub struct DirectHeaderTrace {
    pub fields: Vec<LinExpr>,
    pub expected_semantic_id: [LinExpr; 2],
}

impl DirectHeaderTrace {
    fn alloc(b: &mut FieldR1csBuilder, header: &BlockHeader) -> Self {
        let fields = noid_chain::consensus::pow::pow_header_fields(header)
            .into_iter()
            .enumerate()
            .filter(|(index, _)| *index != noid_chain::consensus::pow::POW_NONCE_FIELD_INDEX)
            .map(|(_, field)| alloc_block(b, field))
            .collect();
        let semantic_id = digest_lanes(&noid_chain::block_header::semantic_header_id(header));
        Self {
            fields,
            expected_semantic_id: semantic_id.map(|lane| alloc_block(b, lane)),
        }
    }
}

/// Trace twin of the byte sponge over whole field lanes under `tag`. Mirrors
/// `Poseidon2bSponge`: pairs are rate blocks; an odd trailing lane shares its
/// final permutation with the `fill_padding` bytes (0x80 first, 0x01 last of
/// the remaining half-buffer); an even schedule pads one whole rate block.
fn sponge_lanes_trace(
    b: &mut FieldR1csBuilder,
    tag: noid_poseidon2b::native::domain::DomainTag,
    fields: &[LinExpr],
) -> [LinExpr; 2] {
    let [iv0, iv1] = capacity_iv(tag);
    let mut state = [
        LinExpr::zero(),
        LinExpr::zero(),
        LinExpr::constant(flat_of(iv0)),
        LinExpr::constant(flat_of(iv1)),
    ];
    for pair in fields.chunks_exact(2) {
        state[0] = state[0].add(&pair[0]);
        state[1] = state[1].add(&pair[1]);
        state = poseidon2b_permute(b, state);
    }
    if fields.len() % 2 == 1 {
        let mut pad = [0u8; 16];
        pad[0] = 0x80;
        pad[15] |= 0x01;
        state[0] = state[0].add(&fields[fields.len() - 1]);
        state[1] = state[1].add_const(flat_of(Block128::from(u128::from_le_bytes(pad))));
    } else {
        let mut pad = [0u8; 32];
        pad[0] = 0x80;
        pad[31] |= 0x01;
        state[0] = state[0].add_const(flat_of(Block128::from(u128::from_le_bytes(
            pad[..16].try_into().expect("fixed pad lane"),
        ))));
        state[1] = state[1].add_const(flat_of(Block128::from(u128::from_le_bytes(
            pad[16..].try_into().expect("fixed pad lane"),
        ))));
    }
    state = poseidon2b_permute(b, state);
    [state[0].clone(), state[1].clone()]
}

fn bind_direct_semantic_id(b: &mut FieldR1csBuilder, header: &DirectHeaderTrace) {
    debug_assert_eq!(header.fields.len(), header_fields::FIELDS);
    let lanes = sponge_lanes_trace(b, TAG_SEMHDR, &header.fields);
    pin_eq(b, &lanes[0], &header.expected_semantic_id[0]);
    pin_eq(b, &lanes[1], &header.expected_semantic_id[1]);
}

/// Parent-seal witness: the exact parent header replayed under both header
/// domains. The chain-link id (`BLOCKHDR`, nonce included) glues the child's
/// `prev_block_hash` and the shifted epoch-anchor write; the nonce-free
/// projection (`SEMHDR`) glues the verified parent terminal tip. Fixed
/// geometry — independent of every tier.
pub(in crate::acceptance) struct ParentSealTrace {
    pub block_id: [LinExpr; 2],
    pub semantic_id: [LinExpr; 2],
    pub height: LinExpr,
    pub previous_block_id: [LinExpr; 2],
    pub alloc_counter: LinExpr,
}

impl ParentSealTrace {
    pub(in crate::acceptance) fn alloc(b: &mut FieldR1csBuilder, parent: &BlockHeader) -> Self {
        let fields: Vec<LinExpr> = noid_chain::consensus::pow::pow_header_fields(parent)
            .into_iter()
            .map(|field| alloc_block(b, field))
            .collect();
        let block_id = sponge_lanes_trace(b, TAG_BLOCKHDR, &fields);
        let semantic: Vec<LinExpr> = fields
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != noid_chain::consensus::pow::POW_NONCE_FIELD_INDEX)
            .map(|(_, wire)| wire.clone())
            .collect();
        let semantic_id = sponge_lanes_trace(b, TAG_SEMHDR, &semantic);
        let height = fields[header_fields::HEIGHT].clone();
        let previous_block_id = [fields[0].clone(), fields[1].clone()];
        let alloc_counter = fields[header_fields::ALLOC_COUNTER + 1].clone();
        Self {
            block_id,
            semantic_id,
            height,
            previous_block_id,
            alloc_counter,
        }
    }
}

/// The primary statement wires of one assembled block, returned for the
/// HistoryStep-level accumulator bindings.
pub struct BlockSlots {
    /// The sealed semantic header wire set every other slot is pinned against.
    pub header: DirectHeaderTrace,
    pub start_acc: AccumulatorWires,
    pub end_acc: AccumulatorWires,
    pub spine_inputs: Vec<SpineInputsTrace>,
    pub tx_hashes: Vec<[LinExpr; 2]>,
    /// Physical page prefix driving body/action/exact-state geometry.
    pub page_live_bits: Vec<LinExpr>,
    /// Compacted logical-group prefix driving capsule and tx-root geometry.
    pub authorization_live_bits: Vec<LinExpr>,
    /// Bitmap-derived, slot-sorted unique live action prefix. Its physical
    /// permutation source is canonical body order.
    pub compacted_actions: CompactedActionTrace,
    pub exact_state: ExactStateSlotWires,
}

struct BlockSlotsCoreAssembly {
    slots: BlockSlots,
    selected_region: Option<SelectedZkBlockRegionBinding>,
    nonce_seal: DirectBlockNonceSeal,
}

/// Private selected-class handoff for the production outer Block owner. It
/// keeps the ordinary Block statement aliases and the opaque bound region
/// together until the owner has appended its public-IO pins and built the
/// same builder.
pub(in crate::acceptance) struct SelectedZkBlockSlotsAssembly {
    slots: BlockSlots,
    region: SelectedZkBlockRegionBinding,
    nonce_seal: Option<DirectBlockNonceSeal>,
    parent_block_id: [LinExpr; 2],
}

struct DirectBlockNonceSeal {
    template_header: BlockHeader,
    start_accumulator: ChainAccumulator,
    parent_header: BlockHeader,
}

impl DirectBlockNonceSeal {
    /// The relation is nonce-free: sealing only validates that the winning
    /// header is the exact template (any nonce) and that the end boundary is
    /// its exact parent-glued advance. No witness cell changes.
    fn seal(
        self,
        sealed_header: &BlockHeader,
        end_accumulator: &ChainAccumulator,
    ) -> Result<(), DirectBlockSealError> {
        let mut expected_header = self.template_header;
        expected_header.nonce = sealed_header.nonce;
        if expected_header != *sealed_header {
            return Err(DirectBlockSealError::HeaderChanged);
        }
        let expected_end = self
            .start_accumulator
            .advance(&self.parent_header, sealed_header)
            .map_err(|_| DirectBlockSealError::EndAccumulator)?;
        if expected_end != *end_accumulator {
            return Err(DirectBlockSealError::EndAccumulator);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::acceptance) enum DirectBlockSealError {
    AlreadySealed,
    HeaderChanged,
    EndAccumulator,
}

/// Unforgeable authority proving the owning HistoryStep builder has finished
/// before its direct region is finalized.
pub(crate) struct SelectedBlockAssemblyFinalizationSeal(());

impl SelectedZkBlockSlotsAssembly {
    pub(in crate::acceptance) fn slots(&self) -> &BlockSlots {
        &self.slots
    }

    pub(in crate::acceptance) fn region_vk(&self) -> &BlockRegionSidecarVk {
        self.region.vk()
    }

    /// Consume the only nonce authority, replace the explicitly deferred free
    /// inputs, and append the canonical direct transition plus `BLOCKHDR`
    /// tail. No ordinary witness wire is mutable through this API.
    pub(in crate::acceptance) fn seal_direct_tail(
        &mut self,
        b: &mut FieldR1csBuilder,
        sealed_header: &BlockHeader,
        end_accumulator: &ChainAccumulator,
    ) -> Result<(), DirectBlockSealError> {
        let seal = self
            .nonce_seal
            .take()
            .ok_or(DirectBlockSealError::AlreadySealed)?;
        seal.seal(sealed_header, end_accumulator)?;
        append_direct_block_tail(
            b,
            &self.slots.header,
            &self.slots.start_acc,
            &self.slots.end_acc,
            &self.parent_block_id,
        );
        Ok(())
    }

    pub(in crate::acceptance) fn into_region_binding(self) -> SelectedZkBlockRegionBinding {
        assert!(
            self.nonce_seal.is_none(),
            "selected block region cannot finalize before the direct nonce tail"
        );
        self.region
    }
}

pub(in crate::acceptance) fn finalize_selected_zk_block_region(
    assembly: SelectedZkBlockSlotsAssembly,
    total_vars: usize,
) -> Result<BlockRegionPreparation, RegionSidecarError> {
    assembly
        .into_region_binding()
        .finalize_after_block_build(SelectedBlockAssemblyFinalizationSeal(()), total_vars)
}

/// Canonical authorization entry. The proof bundle is owned and cannot be
/// omitted, replaced by a transparent proof, or selected by a runtime mode.
pub(in crate::acceptance) fn build_block_slots_selected_zk(
    b: &mut FieldR1csBuilder,
    start_accumulator: &ChainAccumulator,
    end_accumulator: &ChainAccumulator,
    components: &HistoryStepBlockComponents,
    sealed_header: &BlockHeader,
    tier: usize,
    proofs: PreparedSelectedZkAuthorizations,
    parent_header: &BlockHeader,
    parent_block_id: &[LinExpr; 2],
    profile: BlockRelationProfile,
) -> SelectedZkBlockSlotsAssembly {
    let mut assembly = build_block_slots_selected_zk_prefix(
        b,
        start_accumulator,
        end_accumulator,
        components,
        sealed_header,
        tier,
        proofs,
        parent_header,
        parent_block_id,
        profile,
    );
    assembly
        .seal_direct_tail(b, sealed_header, end_accumulator)
        .expect("an immediate direct block assembly seals its exact input");
    assembly
}

/// Build every direct-Block row except the class-fixed direct tail. Only
/// the owning HistoryStep may retain this private capability across PoW.
/// The tail itself is nonce-free; the split exists so the owner appends it
/// after its public-IO pins in one canonical row order.
pub(in crate::acceptance) fn build_block_slots_selected_zk_prefix(
    b: &mut FieldR1csBuilder,
    start_accumulator: &ChainAccumulator,
    end_accumulator: &ChainAccumulator,
    components: &HistoryStepBlockComponents,
    sealed_header: &BlockHeader,
    tier: usize,
    proofs: PreparedSelectedZkAuthorizations,
    parent_header: &BlockHeader,
    parent_block_id: &[LinExpr; 2],
    profile: BlockRelationProfile,
) -> SelectedZkBlockSlotsAssembly {
    assert!(
        crate::region_sidecar::selected_zk_block_geometry(tier).is_some(),
        "selected backend tier is not canonical"
    );
    let mut assembly = build_selected_zk_block_slots_core(
        b,
        start_accumulator,
        end_accumulator,
        components,
        sealed_header,
        tier,
        proofs,
        parent_header,
        parent_block_id,
        profile,
    );
    let region = assembly
        .selected_region
        .take()
        .expect("selected backend returned its opaque bound region");
    SelectedZkBlockSlotsAssembly {
        slots: assembly.slots,
        region,
        nonce_seal: Some(assembly.nonce_seal),
        parent_block_id: [parent_block_id[0].clone(), parent_block_id[1].clone()],
    }
}

fn build_selected_zk_block_slots_core(
    b: &mut FieldR1csBuilder,
    start_accumulator: &ChainAccumulator,
    end_accumulator: &ChainAccumulator,
    components: &HistoryStepBlockComponents,
    sealed_header: &BlockHeader,
    tier: usize,
    authorization_proofs: PreparedSelectedZkAuthorizations,
    parent_header: &BlockHeader,
    parent_block_id: &[LinExpr; 2],
    profile: BlockRelationProfile,
) -> BlockSlotsCoreAssembly {
    let financial_config = profile.native_financial_config();
    let sequential_config = profile.native_sequential_config();
    if profile == BlockRelationProfile::LegacyV1 {
        assert!(
            components.v2_contract_inputs.is_empty(),
            "legacy relation has no contract openings"
        );
    }
    assert_eq!(
        components.tx_body_inputs.len(),
        components.tx_body_hashes.len()
    );
    let n_real_pages = components.user_page_count;
    let effective_page_count = components.effective_page_count();
    if profile == BlockRelationProfile::LegacyV1 {
        assert_eq!(
            noid_chain::consensus::paged_spend::BlockProofClass::for_page_count(
                effective_page_count
            )
            .map(|class| class.page_capacity()),
            Some(tier),
            "legacy Block capacity must match its physical page class"
        );
    } else {
        assert!(effective_page_count <= tier, "candidate capacity exceeded");
    }

    let mut ledger = b.num_wires();

    // ---- Primary statement wires: exact header and accumulator boundary.
    let header = DirectHeaderTrace::alloc(b, sealed_header);
    let start_acc = AccumulatorWires::alloc(b, start_accumulator);
    let end_acc = AccumulatorWires::alloc(b, end_accumulator);

    crate::acceptance::row_ledger_mark(b, &mut ledger, "slots: statement wires");
    use header_fields as hf;
    // Parent continuity and child accumulator fields bind directly to the
    // sealed header. The chain link runs through the derived parent block
    // id: the semantic start tip is glued to the same parent header by the
    // owning HistoryStep's parent seal.
    for lane in 0..2 {
        pin_eq(
            b,
            &parent_block_id[lane],
            &header.fields[hf::PREV_BLOCK_HASH + lane],
        );
    }
    pin_eq(
        b,
        &end_acc.active_slot_count,
        &header.fields[hf::ACTIVE_SLOT_COUNT],
    );
    pin_eq(b, &end_acc.alloc_counter, &header.fields[hf::ALLOC_COUNTER]);
    crate::acceptance::row_ledger_mark(b, &mut ledger, "slots: direct header boundary");
    // ---- Tx8x2 body-spine component. Region mode moves the whole final
    // 31-permutation-per-tx replay onto the shared walk A (compress tree +
    // TAG_TX8X2 wrap): only the statement wires are allocated here — the SAME
    // wire vectors the inline slot returns, so every downstream consumer
    // (tx-root leaves, owner-auth tx_body_hash pins, claim lanes) is
    // untouched — and the handoff carries them into the plural discharge.
    // The inline killshot proof is not consumed in-trace (nodes still verify
    // it natively; π proves the statement directly).
    // Tier capacity: one coinbase plus exactly `tier` body-suffix slots. The
    // real block-order bodies are followed by canonical protocol ghosts. On a
    // payout height suffix slot zero is the payout and at most `tier - 1`
    // physical user pages follow; otherwise all `tier` suffix slots are
    // available to users. The relation selects one fixed user view below.
    let n_real_txs = components.tx_body_inputs.len();
    let tx_delta = 1;
    let cap_txs = tier + tx_delta;
    assert!(
        !components.tx_body_inputs.is_empty(),
        "selected Block carries a body"
    );
    assert_eq!(
        n_real_txs,
        n_real_pages + tx_delta + usize::from(components.has_development_payout),
        "body components contain coinbase, optional payout, and user pages"
    );
    let mut spine_natives: Vec<SpineInputs> = components.tx_body_inputs.clone();
    let mut hash_natives: Vec<[Block128; 2]> = components.tx_body_hashes.clone();
    if cap_txs > n_real_txs {
        let ghost_body = noid_gkr::ghost_tx::ghost_tx_body();
        let ghost_spine = noid_gkr::spine_statement::spine_inputs_from_body(&ghost_body);
        let ghost_hash = noid_gkr::ghost_tx::ghost_tx_body_hash();
        for _ in n_real_txs..cap_txs {
            spine_natives.push(ghost_spine.clone());
            hash_natives.push(ghost_hash);
        }
    }
    let spine_inputs: Vec<SpineInputsTrace> = spine_natives
        .iter()
        .map(|input| SpineInputsTrace::alloc(b, input))
        .collect();
    let tx_hashes: Vec<[LinExpr; 2]> = hash_natives
        .iter()
        .map(|hash| std::array::from_fn(|lane| alloc_block(b, hash[lane])))
        .collect();
    let user_body_base = 1 + usize::from(components.has_development_payout);
    let spine_region_data = Some(spine_region_data_from_wires(
        b,
        &spine_natives,
        &hash_natives,
        &spine_inputs,
        &tx_hashes,
        &components.v2_contract_inputs,
        user_body_base,
        profile,
    ));

    crate::acceptance::row_ledger_mark(b, &mut ledger, "slots: spine (tiles+tree data)");
    // ---- Physical page liveness. Page/action/exact-state geometry follows
    // this prefix; logical authorization liveness is derived later by the
    // START..END scanner and is intentionally a separate quantity.
    let page_live_bits: Vec<LinExpr> = (0..tier)
        .map(|i| {
            let v = Block128::from(if i < n_real_pages { 1u128 } else { 0u128 });
            alloc_block(b, v)
        })
        .collect();
    for wire in &page_live_bits {
        let square = mul(b, wire, wire);
        pin_eq(b, &square, wire);
    }
    for index in 0..page_live_bits.len().saturating_sub(1) {
        let not_previous = page_live_bits[index].add_const(F128::ONE);
        let dead_then_live = mul(b, &page_live_bits[index + 1], &not_previous);
        pin_zero(b, &dead_then_live);
    }
    let body_user_slots = tier;

    // Canonical body-order action candidates. Coinbase has exactly one live
    // mint, the selected payout view contributes two schedule-gated mints,
    // and each fixed user view contributes its eight input and two output
    // bitmap positions. Dyadic authorization PADs have no action slots.
    let user_action_slots = tier.saturating_mul(noid_tx::TX_ACTIONS);
    let mut action_candidates = Vec::with_capacity(user_action_slots + 3);
    let mut selected_input_bits = Vec::with_capacity(tier.saturating_mul(noid_tx::TX_INPUTS));
    let mut selected_output_bits = Vec::with_capacity(tier.saturating_mul(noid_tx::TX_OUTPUTS) + 3);
    let coinbase = bind_coinbase_action_with_amount(b, &spine_inputs[0]);
    for lane in 0..2 {
        pin_eq(
            b,
            &coinbase.action.owner[lane],
            &header.fields[hf::MINER + lane],
        );
    }
    selected_output_bits.push(coinbase.action.live.clone());
    action_candidates.push(coinbase.action);
    let coinbase_amount = coinbase.amount;
    let coinbase_amount_bits: [Wire; 64] = coinbase.amount_bits;

    crate::acceptance::row_ledger_mark(b, &mut ledger, "slots: liveness bits");
    // ---- exact_state component + its statement anchors. The production
    // relation consumes the authoritative sibling frontier and derives the
    // fixed-capacity paired local/upper schedule.
    let structural_es = &components.exact_state;
    let geometry = profile.geometry(tier);
    let (touched_capacity, segment_capacity) =
        (geometry.touched_capacity, geometry.segment_capacity);
    let (exact_state, es_region_data) = build_exact_state_structural_region_slot(
        b,
        structural_es,
        touched_capacity,
        segment_capacity,
    )
    .expect("native-verified structural exact-state carrier");
    let es_region_data = Some(es_region_data);
    let parent_root = start_acc.state_root.clone();
    let child_root = [
        header.fields[hf::STATE_ROOT].clone(),
        header.fields[hf::STATE_ROOT + 1].clone(),
    ];
    let exact_state_depth = bind_exact_state_header_roots_dynamic(
        b,
        &exact_state.roots,
        &parent_root,
        &start_acc.log_slots,
        &child_root,
        &header.fields[hf::LOG_SLOTS],
    );

    let prepared_allocation = match profile {
        BlockRelationProfile::ScheduledV2(config) => PreparedDevelopmentAllocation::new(
            b,
            &header.fields[hf::HEIGHT],
            &exact_state_depth.child,
            &spine_inputs[1].leaves[noid_tx::body_hash::TX8X2_LEAF_OUTPUT0_DATA][1],
            config.schedule(),
        ),
        _ => PreparedDevelopmentAllocation::legacy(
            b,
            &header.fields[hf::HEIGHT],
            &exact_state_depth.child,
            &spine_inputs[1].leaves[noid_tx::body_hash::TX8X2_LEAF_OUTPUT0_DATA][1],
        ),
    };
    let allocation = prepared_allocation.trace();
    let ghost_spine_native =
        noid_gkr::spine_statement::spine_inputs_from_body(&noid_gkr::ghost_tx::ghost_tx_body());
    let ghost_spine = constant_spine_inputs_trace(&ghost_spine_native);
    let payout_spine =
        select_spine_inputs_trace(b, &allocation.payout_due, &spine_inputs[1], &ghost_spine);
    let payout = bind_development_payout_action(b, &payout_spine, &allocation.payout_due);
    pin_eq(b, &payout.amount_each, &allocation.payout_each);
    for action in payout.actions {
        selected_output_bits.push(action.live.clone());
        action_candidates.push(action);
    }

    // Select one class-fixed user view from the shared suffix. On payout
    // heights user i is raw suffix i+1; otherwise it is raw suffix i. The
    // final payout-height user position selects the protocol ghost, preserving
    // the original B255 Meta geometry instead of allocating a 257th spine.
    let user_spine_inputs = (0..tier)
        .map(|index| {
            let payout_position = spine_inputs.get(index + 2).unwrap_or(&ghost_spine);
            select_spine_inputs_trace(
                b,
                &allocation.payout_due,
                payout_position,
                &spine_inputs[index + 1],
            )
        })
        .collect::<Vec<_>>();
    let ghost_hash_native = noid_gkr::ghost_tx::ghost_tx_body_hash();
    let ghost_hash = [
        const_block(ghost_hash_native[0]),
        const_block(ghost_hash_native[1]),
    ];
    let user_tx_hashes = (0..tier)
        .map(|index| {
            let payout_position = tx_hashes.get(index + 2).unwrap_or(&ghost_hash);
            std::array::from_fn(|lane| {
                select_expr(
                    b,
                    &allocation.payout_due,
                    &payout_position[lane],
                    &tx_hashes[index + 1][lane],
                )
            })
        })
        .collect::<Vec<_>>();

    // Coinbase and a live payout anchor to the direct parent. Every selected
    // user view anchors to the epoch selected by the accumulator; dead views
    // are complete canonical ghosts.
    bind_tx_epoch_anchors(
        b,
        parent_block_id,
        &end_acc.epoch_anchor_id,
        &spine_inputs[0],
        &payout_spine,
        &user_spine_inputs,
        &allocation.payout_due,
        &page_live_bits,
    );

    // A payout consumes one position in the effective proof class. This
    // circuit constraint is the proof-side twin of template/resource
    // selection and prevents a due block from hiding a tier-sized user suffix.
    let payout_over_capacity = mul(
        b,
        &allocation.payout_due,
        page_live_bits
            .last()
            .expect("canonical block tiers are non-empty"),
    );
    pin_zero(b, &payout_over_capacity);

    crate::acceptance::row_ledger_mark(b, &mut ledger, "slots: exact-state");
    // ---- Physical page arithmetic followed by the fixed PagedSpend scan.
    // Pages keep the existing action/exact-state surface; only complete END
    // records enter logical tx-root, fee and authorization slots.
    assert_eq!(body_user_slots, geometry.tier);
    let n_auth_slots = geometry.auth_tiles;
    assert_eq!(n_auth_slots, geometry.auth_tiles);
    assert_eq!(
        tx_delta, 1,
        "selected raw body suffix begins after coinbase"
    );
    assert_eq!(
        spine_inputs.len(),
        body_user_slots + tx_delta,
        "selected authorization requires every canonical body spine"
    );

    let mut page_surfaces = Vec::with_capacity(body_user_slots);
    let mut user_public_arithmetic = Vec::with_capacity(body_user_slots);
    for index in 0..body_user_slots {
        let (surface, arithmetic) = append_page_action_surface(
            b,
            &user_spine_inputs[index],
            &page_live_bits[index],
            &mut action_candidates,
            &mut selected_input_bits,
            &mut selected_output_bits,
            profile,
        );
        page_surfaces.push(surface);
        user_public_arithmetic.push(arithmetic);
    }
    if profile.native_namespace() && profile.native_header_capacity().is_none() {
        for (surface, arithmetic) in page_surfaces.iter().zip(&user_public_arithmetic) {
            super::trace::native_assets::actions::bind_ordinary_native_namespace(
                b, surface, arithmetic,
            );
        }
    }
    crate::acceptance::row_ledger_mark(b, &mut ledger, "slots: page surfaces");
    let v2_contract_views = profile.contracts().then(|| {
        select_v2_contract_views(
            b,
            spine_region_data
                .as_ref()
                .expect("selected spine region data"),
            &allocation.payout_due,
            profile.contract_slots(),
        )
    });
    let v2_contract_policy = v2_contract_views
        .as_ref()
        .map(|views| bind_v2_contract_policy(b, views, &allocation.height_bits));
    crate::acceptance::row_ledger_mark(b, &mut ledger, "slots: v2 contract policy");
    let (paged_spend, financial_groups, financial_authorizations, financial_authorization_count) =
        if financial_config.is_some() {
            let financial = super::trace::paged_spend::bind_financial_paged_spend_stream(
                b,
                &user_spine_inputs,
                &user_tx_hashes,
                &page_live_bits,
                &page_surfaces,
                &user_public_arithmetic,
            );
            (
                financial.stream,
                Some(financial.native_groups),
                Some(financial.authorizations),
                Some(financial.authorization_count),
            )
        } else {
            let stream = if profile.native_header_capacity().is_some() {
                super::trace::paged_spend::bind_paged_spend_stream_v2_1(
                    b,
                    &user_spine_inputs,
                    &user_tx_hashes,
                    &page_live_bits,
                    &page_surfaces,
                    &user_public_arithmetic,
                )
            } else {
                bind_paged_spend_stream(
                    b,
                    &user_spine_inputs,
                    &user_tx_hashes,
                    &page_live_bits,
                    &page_surfaces,
                    &user_public_arithmetic,
                )
            };
            (stream, None, None, None)
        };
    let native_headers = if let Some(limit) = profile
        .native_header_capacity()
        .filter(|_| financial_config.is_none())
    {
        let chain = noid_poseidon2b::primitives::Address(
            noid_chain::state::native_assets::native_chain_id(),
        )
        .as_fields()
        .map(const_block);
        let headers = super::trace::native_assets::header::bind_native_headers(
            b,
            &user_spine_inputs,
            &page_surfaces,
            &paged_spend.native_pages,
            limit,
            &chain,
        );
        let activation = match profile {
            BlockRelationProfile::ScheduledV2(config) => config.authorization_activation().unwrap(),
            _ => unreachable!("native assets use the scheduled profile"),
        };
        let height_bits: Vec<_> = allocation
            .height_bits
            .iter()
            .copied()
            .map(LinExpr::from_wire)
            .collect();
        let activation_bits: Vec<_> = (0..64)
            .map(|bit| LinExpr::constant(flat_const(u128::from((activation >> bit) & 1))))
            .collect();
        let before_activation =
            super::trace::native_assets::arithmetic::less_than(b, &height_bits, &activation_bits);
        for header in &headers {
            let early_native = mul(b, &header.live, &before_activation);
            pin_zero(b, &early_native);
        }
        Some(headers)
    } else {
        None
    };
    let financial_headers = financial_config.map(|financial| {
        let chain = noid_poseidon2b::primitives::Address(
            noid_chain::state::native_assets::native_chain_id(),
        )
        .as_fields()
        .map(const_block);
        let headers = super::trace::native_assets::header::bind_financial_native_headers(
            b,
            &user_spine_inputs,
            &page_surfaces,
            &paged_spend.native_pages,
            profile
                .native_header_capacity()
                .expect("financial header capacity"),
            &chain,
        );
        let activation = match profile {
            BlockRelationProfile::ScheduledV2(config) => config.authorization_activation().unwrap(),
            _ => unreachable!("financial operations use a scheduled profile"),
        };
        let height_bits = allocation
            .height_bits
            .iter()
            .copied()
            .map(LinExpr::from_wire)
            .collect::<Vec<_>>();
        let activation_bits = (0..64)
            .map(|bit| LinExpr::constant(flat_const(u128::from((activation >> bit) & 1))))
            .collect::<Vec<_>>();
        let before =
            super::trace::native_assets::arithmetic::less_than(b, &height_bits, &activation_bits);
        for header in &headers {
            let early = mul(b, &header.header.live, &before);
            pin_zero(b, &early);
        }
        if sequential_config.is_some() {
            super::trace::native_assets::financial_kernel::bind_financial_sequential_headers(
                b, &headers,
            );
        } else {
            super::trace::native_assets::financial_kernel::bind_financial_phase_headers(
                b,
                financial.phase,
                &headers,
            );
        }
        headers
    });
    let native_action_selectors = if let Some(headers) = financial_headers.as_ref() {
        Some(
            super::trace::native_assets::actions::bind_financial_action_selectors(
                b,
                &page_surfaces,
                &user_public_arithmetic,
                &paged_spend.native_pages,
                headers,
            ),
        )
    } else {
        native_headers.as_ref().map(|headers| {
            super::trace::native_assets::actions::bind_native_action_selectors(
                b,
                &page_surfaces,
                &user_public_arithmetic,
                &paged_spend.native_pages,
                headers,
            )
        })
    };
    assert_eq!(paged_spend.groups.len(), n_auth_slots);
    let trade_authorization_advice = sequential_config.map(|config| {
        super::trace::native_assets::sequential_trade::authorization::allocate_trade_owner_advice(
            b,
            config.policies,
            financial_headers.as_ref().expect("sequential headers"),
            &components.native_trade_batches,
        )
    });
    let merged_authorizations = trade_authorization_advice.as_ref().map(|advice| {
        let flags = page_surfaces
            .iter()
            .map(|surface| surface.contract.clone())
            .collect::<Vec<_>>();
        let authorities = v2_contract_policy
            .as_ref()
            .map_or(&[][..], |policy| policy.expected_authorities.as_slice());
        super::trace::native_assets::sequential_trade::authorization::merge_trade_authorizations(
            b,
            financial_authorizations
                .as_ref()
                .expect("financial authorization groups"),
            &flags,
            authorities,
            advice,
        )
    });
    let authorization_groups = merged_authorizations
        .as_ref()
        .map(|prefix| &prefix.groups)
        .or(financial_authorizations.as_ref())
        .unwrap_or(&paged_spend.groups);
    let authorization_count = merged_authorizations
        .as_ref()
        .map(|prefix| &prefix.count)
        .or(financial_authorization_count.as_ref())
        .unwrap_or(&paged_spend.logical_count);
    let logical_count = block_from_alias(b, &paged_spend.logical_count).0 as usize;
    assert_eq!(
        block_from_alias(b, authorization_count).0 as usize,
        components.authorization_inputs.len(),
        "native logical authorization count must equal the constrained END prefix"
    );
    let authorization_live_bits = authorization_groups
        .iter()
        .map(|group| group.live.clone())
        .collect::<Vec<_>>();
    let user_plus_coinbase_count = alloc_block(b, Block128::from((logical_count + 1) as u128));
    pin_u64_successor(b, &paged_spend.logical_count, &user_plus_coinbase_count);
    let expected_tx_count =
        integer_add_no_overflow(b, &user_plus_coinbase_count, &allocation.payout_due, 64);
    let tx_count = alloc_block(
        b,
        Block128::from(
            (logical_count + 1 + usize::from(components.has_development_payout)) as u128,
        ),
    );
    pin_eq(b, &tx_count, &expected_tx_count);

    // Coinbase, the optional system payout, and compacted logical user txids
    // form the universal tx tree. The fixed circuit positions below mux the
    // payout into index one on due heights and shift user groups by one; on
    // ordinary heights users begin directly at index one.
    assert!(
        !components.tx_root_inputs.is_empty(),
        "selected Block carries the canonical logical transaction root"
    );
    let logical_user_hashes = if financial_config.is_some() {
        paged_spend
            .groups
            .iter()
            .take(logical_count)
            .map(|group| {
                group
                    .logical_txid
                    .each_ref()
                    .map(|lane| block_from_alias(b, lane))
            })
            .collect::<Vec<_>>()
    } else {
        components
            .authorization_inputs
            .iter()
            .map(|input| input.tx_body_hash)
            .collect::<Vec<_>>()
    };
    let logical_hash_natives = std::iter::once(components.tx_body_hashes[0])
        .chain(
            components
                .has_development_payout
                .then(|| components.tx_body_hashes[1]),
        )
        .chain(logical_user_hashes)
        .collect::<Vec<_>>();
    assert_eq!(
        logical_hash_natives.len(),
        components.tx_root_inputs.len(),
        "one native tx-root path per logical transaction"
    );
    let mut logical_hash_wires = Vec::with_capacity(tier + 1);
    let mut logical_live_bits = Vec::with_capacity(tier + 1);
    logical_hash_wires.push(tx_hashes[0].clone());
    logical_live_bits.push(LinExpr::constant(F128::ONE));
    for logical_suffix_index in 0..tier {
        let (due_hash, due_live) = if logical_suffix_index == 0 {
            (tx_hashes[1].clone(), LinExpr::constant(F128::ONE))
        } else {
            let group = &paged_spend.groups[logical_suffix_index - 1];
            (group.logical_txid.clone(), group.live.clone())
        };
        let ordinary_group = &paged_spend.groups[logical_suffix_index];
        let ordinary_hash = ordinary_group.logical_txid.clone();
        let ordinary_live = ordinary_group.live.clone();
        logical_hash_wires.push(std::array::from_fn(|lane| {
            select_expr(
                b,
                &allocation.payout_due,
                &due_hash[lane],
                &ordinary_hash[lane],
            )
        }));
        logical_live_bits.push(select_expr(
            b,
            &allocation.payout_due,
            &due_live,
            &ordinary_live,
        ));
    }
    let tx_root_region_data = Some(tx_root_region_capacity_handoff(
        b,
        &components.tx_root_inputs,
        &logical_hash_natives,
        &logical_hash_wires,
        &logical_live_bits,
    ));
    let merkle_root = tx_root_region_data
        .as_ref()
        .expect("selected Meta-B logical tx-root handoff")
        .root_w
        .clone();
    let header_root = [
        header.fields[hf::TX_ROOT].clone(),
        header.fields[hf::TX_ROOT + 1].clone(),
    ];
    bind_tx_root_count_wrapper(b, &merkle_root, &tx_count, &header_root);
    crate::acceptance::row_ledger_mark(b, &mut ledger, "slots: PagedSpend+logical tx-root");

    let canonical_authorization = match v2_contract_policy
        .as_ref()
        .filter(|_| sequential_config.is_none())
    {
        Some(policy) => mint_v2_selected_zk_authorization_capability(
            b,
            authorization_groups,
            &page_surfaces,
            policy,
        ),
        None => mint_canonical_selected_zk_authorization_capability(b, authorization_groups),
    };
    assert_eq!(
        user_public_arithmetic.len(),
        body_user_slots,
        "one public-arithmetic trace per physical user body slot"
    );
    crate::acceptance::row_ledger_mark(b, &mut ledger, "slots: page arithmetic+logical auth");
    let financial_fees = if let Some(headers) = financial_headers.as_ref() {
        Some(
            super::trace::fee_arithmetic::bind_financial_block_fee_arithmetic(
                b,
                &paged_spend.groups[..tier],
                &financial_groups.as_ref().expect("financial group flags")[..tier],
                headers,
                &start_acc.active_slot_count,
                &exact_state_depth.parent,
                &exact_state_depth.child,
                &allocation.miner_subsidy,
                &coinbase_amount,
                &coinbase_amount_bits,
            ),
        )
    } else {
        bind_block_fee_arithmetic(
            b,
            &paged_spend.groups[..tier],
            &start_acc.active_slot_count,
            &exact_state_depth.parent,
            &exact_state_depth.child,
            &allocation.miner_subsidy,
            &coinbase_amount,
            &coinbase_amount_bits,
        );
        None
    };
    crate::acceptance::row_ledger_mark(b, &mut ledger, "slots: fee/burn/coinbase arithmetic");
    let selected_region = Some(bind_selected_zk_block_region(
        b,
        canonical_authorization,
        authorization_proofs,
        es_region_data
            .as_ref()
            .expect("selected exact-state region data"),
        tx_root_region_data
            .as_ref()
            .expect("selected tx-root region data"),
        spine_region_data
            .as_ref()
            .expect("selected spine region data"),
        geometry,
    ));
    crate::acceptance::row_ledger_mark(
        b,
        &mut ledger,
        "slots: selected auth+Meta/all-tiles assembly",
    );
    if matches!(profile, BlockRelationProfile::ScheduledV2(_)) {
        pin_eq(b, &allocation.v2_active, &LinExpr::constant(F128::ONE));
    }
    prepared_allocation.finish(b);
    // Only the deadline-selected authorization address is needed before the
    // dyadically aligned selected-region allocation. Bind the remaining
    // contract shape and execution semantics afterwards to avoid turning a
    // few hundred useful rows into an otherwise empty 2^13 alignment gap.
    if let Some(policy) = v2_contract_policy.as_ref() {
        bind_v2_contract_partition(
            b,
            &page_surfaces,
            v2_contract_views.as_ref().expect("object views"),
            profile.native_sequential_config().is_none(),
        );
        bind_v2_contract_execution(
            b,
            &user_spine_inputs,
            &page_surfaces,
            v2_contract_views.as_ref().expect("object views"),
            policy,
            matches!(profile, BlockRelationProfile::ScheduledV2(config) if config.authorization_activation().is_some()),
        );
    }
    crate::acceptance::row_ledger_mark(b, &mut ledger, "slots: v2 contract execution");
    crate::acceptance::row_ledger_mark(b, &mut ledger, "slots: wallet plural/sidecar assembly");
    // Totals: transaction and action counts now come from the same liveness
    // and bitmap wires that feed compaction. All sums are INTEGERS
    // (ripple-carry over tower bits), not GF(2^128) XOR.
    // Tier capacity: count lanes bind to the same liveness sum that gates the
    // selected proof tiles. TX_COUNT includes the mandatory coinbase.
    let live_input_sum = pin_u64_sum(b, &selected_input_bits);
    let output_sum = pin_u64_sum(b, &selected_output_bits);

    // Exact active-slot counter equation as unsigned integers:
    // parent + all mints (including coinbase) = child + all spends.
    // Both additions reject u64 overflow instead of silently wrapping in the
    // characteristic-two field.
    bind_active_slot_counter_delta(
        b,
        &start_acc.active_slot_count,
        &header.fields[hf::ACTIVE_SLOT_COUNT],
        &live_input_sum,
        &output_sum,
    );

    let class = super::shape::ShapeClass { tier };
    assert_eq!(
        action_candidates.len(),
        class.action_candidate_capacity(),
        "three fixed system candidates plus ten per tier user slot"
    );
    let input_capacity = match profile {
        BlockRelationProfile::ScheduledV2(config) => config.max_live_inputs(),
        _ => class.spend_capacity(),
    };
    bind_block_input_limit(b, &live_input_sum, input_capacity);
    let action_live_capacity = geometry.touched_capacity;
    if profile.native_namespace() {
        let mut native_mints = vec![LinExpr::zero(); 3];
        if let Some(selectors) = native_action_selectors.as_ref() {
            native_mints.extend(selectors.native.iter().enumerate().map(|(index, native)| {
                if index % 10 >= 8 {
                    native.clone()
                } else {
                    LinExpr::zero()
                }
            }));
        } else {
            native_mints.resize(action_candidates.len(), LinExpr::zero());
        }
        super::trace::action_compaction::bind_native_mint_packed_values_body_order(
            b,
            &mut action_candidates,
            &start_acc.alloc_counter,
            &header.fields[hf::ALLOC_COUNTER],
            &header.fields[hf::HEIGHT],
            &native_mints,
        );
    } else {
        bind_mint_packed_values_body_order(
            b,
            &mut action_candidates,
            &start_acc.alloc_counter,
            &header.fields[hf::ALLOC_COUNTER],
            &header.fields[hf::HEIGHT],
        );
    }
    if let Some(selectors) = native_action_selectors.as_ref() {
        let openings = components
            .native_openings
            .iter()
            .map(|opening| (opening.root(), *opening))
            .collect::<std::collections::HashMap<_, _>>();
        let capacity = match profile {
            BlockRelationProfile::ScheduledV2(config) => config.native_action_capacity().unwrap(),
            _ => unreachable!("native actions use the scheduled profile"),
        };
        if let Some(financial) = financial_config {
            use super::trace::native_assets::{
                financial_actions::{bind_financial_actions, bind_sequential_financial_actions},
                financial_kernel::{self, FinancialKernelBody, FinancialKernelBoundary},
            };
            let headers = financial_headers.as_ref().expect("financial headers");
            let mut native_ledger = b.num_wires();
            let actions = if sequential_config.is_some() {
                bind_sequential_financial_actions(
                    b,
                    &action_candidates[3..],
                    selectors,
                    &paged_spend.native_pages,
                    headers,
                    capacity,
                    |root| openings.get(&root).copied(),
                )
            } else {
                bind_financial_actions(
                    b,
                    &action_candidates[3..],
                    selectors,
                    &paged_spend.native_pages,
                    headers,
                    capacity,
                    |root| openings.get(&root).copied(),
                )
            };
            crate::acceptance::row_ledger_mark(
                b,
                &mut native_ledger,
                "native: complete action table",
            );
            let mut definitions = components
                .native_openings
                .iter()
                .copied()
                .filter(noid_tx::native_assets::NativeOpening::is_auxiliary)
                .collect::<Vec<_>>();
            definitions.sort_by_key(|opening| opening.root().0);
            let body = FinancialKernelBody {
                actions: &actions,
                headers,
                surfaces: &page_surfaces,
                pages: &paged_spend.native_pages,
            };
            let boundary = FinancialKernelBoundary {
                height: &header.fields[hf::HEIGHT],
                parent_id: parent_block_id,
                parent_alloc_counter: &start_acc.alloc_counter,
            };
            let prepared = if sequential_config.is_some() {
                financial_kernel::bind_financial_sequential_preparation(
                    b,
                    financial.kernel,
                    &body,
                    &boundary,
                    &definitions,
                )
            } else if financial.phase == financial_kernel::FinancialKernelPhase::Settlement {
                financial_kernel::bind_financial_settlement_preparation(
                    b,
                    financial.kernel,
                    &body,
                    &boundary,
                    &definitions,
                )
            } else {
                financial_kernel::bind_financial_preparation(
                    b,
                    financial.kernel,
                    &body,
                    &boundary,
                    &definitions,
                )
            };
            crate::acceptance::row_ledger_mark(b, &mut native_ledger, "native: typed preparation");
            let fees = &financial_fees
                .as_ref()
                .expect("financial fee context")
                .required_by_header;
            if let Some(trade_config) = sequential_config {
                financial_kernel::bind_financial_sequential_owner_operations(
                    b, &body, &prepared, &boundary, fees,
                );
                crate::acceptance::row_ledger_mark(
                    b,
                    &mut native_ledger,
                    "native: launch and NFT rights",
                );
                use super::trace::native_assets::sequential_trade::{
                    authorization::bind_trade_owner_advice,
                    fees::bind_trade_growth_price,
                    kernel::{bind_trade_kernel, TradeKernelContext},
                };
                let growth = bind_trade_growth_price(
                    b,
                    &financial_fees
                        .as_ref()
                        .expect("financial fee context")
                        .block
                        .pressure_multiplier,
                );
                let chain = noid_poseidon2b::primitives::Address(
                    noid_chain::state::native_assets::native_chain_id(),
                )
                .as_fields()
                .map(const_block);
                let context = TradeKernelContext {
                    chain: &chain,
                    epoch_anchor: &end_acc.epoch_anchor_id,
                    parent_id: parent_block_id,
                    height: &header.fields[hf::HEIGHT],
                    parent_alloc_counter: &start_acc.alloc_counter,
                    growth_per_slot: &growth,
                };
                let trade = bind_trade_kernel(
                    b,
                    trade_config,
                    &context,
                    headers,
                    &actions,
                    &prepared.definitions,
                    &components.native_trade_batches,
                );
                crate::acceptance::row_ledger_mark(
                    b,
                    &mut native_ledger,
                    "native: sequential trade kernel",
                );
                bind_trade_owner_advice(
                    b,
                    trade_authorization_advice
                        .as_ref()
                        .expect("sequential Owner advice"),
                    &trade.authorizations,
                );
                crate::acceptance::row_ledger_mark(
                    b,
                    &mut native_ledger,
                    "native: Owner advice binding",
                );
            } else if financial.phase != financial_kernel::FinancialKernelPhase::Settlement {
                financial_kernel::bind_financial_owner_operations(
                    b, &body, &prepared, &boundary, fees,
                );
            }
            if sequential_config.is_none()
                && financial.phase != financial_kernel::FinancialKernelPhase::Admission
            {
                financial_kernel::bind_financial_settlements(
                    b,
                    financial.kernel,
                    &body,
                    &prepared,
                    &header.fields[hf::HEIGHT],
                    fees,
                    &[],
                );
            }
        } else {
            let native_actions = super::trace::native_assets::actions::bind_native_actions(
                b,
                &action_candidates[3..],
                selectors,
                &paged_spend.native_pages,
                native_headers.as_ref().expect("native headers"),
                &header.fields[hf::HEIGHT],
                capacity,
                |root| openings.get(&root).copied(),
            );
            super::trace::native_assets::kernel::bind_native_kernel(
                b,
                native_headers.as_ref().expect("native headers"),
                &native_actions,
                &header.fields[hf::HEIGHT],
            );
        }
    }
    crate::acceptance::row_ledger_mark(b, &mut ledger, "slots: native object actions");
    let compacted_actions = compact_action_rows(b, &action_candidates, action_live_capacity);
    crate::acceptance::row_ledger_mark(b, &mut ledger, "slots: action allocator+route+order");

    let paired_cells = selected_region
        .as_ref()
        .map(SelectedZkBlockRegionBinding::paired)
        .expect("selected region carries paired exact-state cells");
    bind_paired_exact_state_transition(
        b,
        &compacted_actions,
        &exact_state,
        paired_cells,
        &exact_state_depth.child,
    );
    crate::acceptance::row_ledger_mark(b, &mut ledger, "slots: exact-state action+paired topology");

    let slots = BlockSlots {
        header,
        start_acc,
        end_acc,
        spine_inputs,
        tx_hashes,
        page_live_bits,
        authorization_live_bits,
        compacted_actions,
        exact_state,
    };
    BlockSlotsCoreAssembly {
        slots,
        selected_region,
        nonce_seal: DirectBlockNonceSeal {
            template_header: *sealed_header,
            start_accumulator: start_accumulator.clone(),
            parent_header: *parent_header,
        },
    }
}

/// The class-fixed relation suffix. Nonce-free: every gadget is fully
/// determined by the semantic template, the start boundary and the derived
/// parent block id supplied by the owning HistoryStep's parent seal.
fn append_direct_block_tail(
    b: &mut FieldR1csBuilder,
    header: &DirectHeaderTrace,
    start_accumulator: &AccumulatorWires,
    end_accumulator: &AccumulatorWires,
    parent_block_id: &[LinExpr; 2],
) {
    use header_fields as hf;

    let mut ledger = b.num_wires();
    let child = DirectChildWires {
        semantic_id: header.expected_semantic_id.clone(),
        prev_block_hash: [
            header.fields[hf::PREV_BLOCK_HASH].clone(),
            header.fields[hf::PREV_BLOCK_HASH + 1].clone(),
        ],
        state_root: [
            header.fields[hf::STATE_ROOT].clone(),
            header.fields[hf::STATE_ROOT + 1].clone(),
        ],
        height: header.fields[hf::HEIGHT].clone(),
        log_slots: header.fields[hf::LOG_SLOTS].clone(),
        active_slot_count: header.fields[hf::ACTIVE_SLOT_COUNT].clone(),
        alloc_counter: header.fields[hf::ALLOC_COUNTER].clone(),
    };
    build_direct_accumulator_transition_slot(
        b,
        start_accumulator,
        &child,
        end_accumulator,
        parent_block_id,
    );

    // Exact `SEMHDR` binding over the same semantic header wires. PoW,
    // difficulty and the nonce-bearing chain-link id remain exclusively in
    // the permanent native header path; the child step's parent seal derives
    // and pins the link id in-circuit one height later.
    bind_direct_semantic_id(b, header);
    debug_assert_eq!(
        b.num_wires() - ledger,
        DIRECT_BLOCK_TAIL_ROWS,
        "canonical direct tail row drift"
    );
    crate::acceptance::row_ledger_mark(b, &mut ledger, "slots: direct accumulator + header hash");
}

#[cfg(test)]
mod tx_epoch_anchor_tests {
    use super::*;
    use noid_core::TowerField;

    fn tail_parent_header(height: u64) -> BlockHeader {
        BlockHeader {
            prev_block_hash: [0x10; 32],
            state_root: [0x22; 32],
            tx_root: [0x2A; 32],
            timestamp: height * 10,
            height,
            miner_address: noid_poseidon2b::primitives::Address([0x66; 32]),
            nonce: height as u128,
            difficulty_target: [0xFF; 32],
            log_slots: 8,
            active_slot_count: 7,
            alloc_counter: 9,
        }
    }

    fn tail_start(parent: &BlockHeader) -> ChainAccumulator {
        ChainAccumulator {
            height: parent.height,
            tip_semantic_id: noid_chain::block_header::semantic_header_id(parent),
            state_root: parent.state_root,
            log_slots: parent.log_slots,
            active_slot_count: parent.active_slot_count,
            alloc_counter: parent.alloc_counter,
            epoch_anchor_id: [0x33; 32],
        }
    }

    fn tail_child(parent: &BlockHeader, nonce: u128) -> BlockHeader {
        BlockHeader {
            prev_block_hash: noid_chain::hash_block_header(parent),
            state_root: [0x44; 32],
            tx_root: [0x55; 32],
            timestamp: parent.timestamp + 10,
            height: parent.height + 1,
            miner_address: noid_poseidon2b::primitives::Address([0x66; 32]),
            nonce,
            difficulty_target: [0xFF; 32],
            log_slots: parent.log_slots,
            active_slot_count: 8,
            alloc_counter: 10,
        }
    }

    fn direct_tail_fixture(
        parent: &BlockHeader,
        sealed_header: &BlockHeader,
        start: &ChainAccumulator,
        end: &ChainAccumulator,
    ) -> (noid_ivc_core::field_r1cs::FieldR1cs, Vec<F128>, usize) {
        let mut builder = FieldR1csBuilder::new();
        let header = DirectHeaderTrace::alloc(&mut builder, sealed_header);
        let start_wires = AccumulatorWires::alloc(&mut builder, start);
        let end_wires = AccumulatorWires::alloc(&mut builder, end);
        let parent_block_id = digest_lanes(&noid_chain::hash_block_header(parent))
            .map(|lane| alloc_block(&mut builder, lane));

        // Represents arbitrary HistoryStep rows placed between the primary
        // statement and the class-fixed direct suffix.
        for index in 0..17u64 {
            builder.alloc_f128(F128 {
                lo: index + 1,
                hi: 0,
            });
        }
        let seal = DirectBlockNonceSeal {
            template_header: *sealed_header,
            start_accumulator: start.clone(),
            parent_header: *parent,
        };
        seal.seal(sealed_header, end)
            .expect("exact sealed template boundary");
        let before_tail = builder.num_wires();
        append_direct_block_tail(
            &mut builder,
            &header,
            &start_wires,
            &end_wires,
            &parent_block_id,
        );
        let tail_rows = builder.num_wires() - before_tail;
        let (matrix, witness) = builder.build();
        (matrix, witness, tail_rows)
    }

    #[test]
    fn direct_tail_is_nonce_free_across_the_epoch_edge() {
        // Parent heights 143 (child 144: boundary block keeps the previous
        // anchor) and 144 (child 145: anchor becomes the derived parent id).
        for parent_height in [143u64, 144] {
            let parent = tail_parent_header(parent_height);
            let start = tail_start(&parent);
            let template = tail_child(&parent, 0);
            let mut renonced = template;
            renonced.nonce = 0xDEAD_BEEF_CAFE_BABEu128;

            let end = start.advance(&parent, &template).unwrap();
            let renonced_end = start.advance(&parent, &renonced).unwrap();
            // The complete boundary is nonce-invariant.
            assert_eq!(end, renonced_end);
            if parent_height == 144 {
                assert_eq!(end.epoch_anchor_id, noid_chain::hash_block_header(&parent));
            } else {
                assert_eq!(end.epoch_anchor_id, start.epoch_anchor_id);
            }

            let (matrix, witness, tail_rows) =
                direct_tail_fixture(&parent, &template, &start, &end);
            let (renonced_matrix, renonced_witness, renonced_tail_rows) =
                direct_tail_fixture(&parent, &renonced, &start, &renonced_end);

            assert_eq!(tail_rows, DIRECT_BLOCK_TAIL_ROWS);
            assert_eq!(renonced_tail_rows, tail_rows);
            assert_eq!(
                matrix.structural_statement_digest(),
                renonced_matrix.structural_statement_digest()
            );
            // The witness itself is identical for every nonce of one
            // template: the relation is nonce-free.
            assert_eq!(witness, renonced_witness);
            assert!(matrix.satisfies(&witness));
        }
    }

    fn active_counter_case(
        parent: u128,
        child: u128,
        spends: u128,
        mints: u128,
    ) -> (noid_ivc_core::field_r1cs::FieldR1cs, Vec<F128>) {
        let mut b = FieldR1csBuilder::new();
        let parent = alloc_block(&mut b, Block128::from(parent));
        let child = alloc_block(&mut b, Block128::from(child));
        let spends = alloc_block(&mut b, Block128::from(spends));
        let mints = alloc_block(&mut b, Block128::from(mints));
        bind_active_slot_counter_delta(&mut b, &parent, &child, &spends, &mints);
        b.build()
    }

    #[test]
    fn active_counter_uses_exact_spend_mint_delta() {
        for (parent, child, spends, mints) in [(7, 8, 2, 3), (7, 5, 3, 1), (0, 1, 0, 1)] {
            let (r1cs, witness) = active_counter_case(parent, child, spends, mints);
            assert!(r1cs.satisfies(&witness));
        }
    }

    #[test]
    fn active_counter_rejects_wrong_delta_and_overflow() {
        for case in [(7, 9, 2, 3), (u64::MAX as u128, 0, 0, 1)] {
            let (r1cs, witness) = active_counter_case(case.0, case.1, case.2, case.3);
            assert!(!r1cs.satisfies(&witness));
        }
    }

    fn start_accumulator() -> ChainAccumulator {
        ChainAccumulator {
            height: 143,
            tip_semantic_id: [0x11; 32],
            state_root: [0x22; 32],
            log_slots: 24,
            active_slot_count: 7,
            alloc_counter: 9,
            epoch_anchor_id: [0x33; 32],
        }
    }

    const TEST_PARENT_BLOCK_ID: [u8; 32] = [0x66; 32];
    const MARKER_LEAF: usize = noid_tx::body_hash::TX8X2_LEAF_FEE;

    fn selected_suffix_case(
        payout_due: bool,
    ) -> (noid_ivc_core::field_r1cs::FieldR1cs, Vec<F128>, [F128; 3]) {
        let mut coinbase = SpineInputs {
            leaves: [[Block128::ZERO; 2]; noid_tx::body_hash::BODY_HASH_LEAVES],
        };
        coinbase.leaves[MARKER_LEAF][0] = Block128::from(1u128);
        let mut first = coinbase.clone();
        let mut second = coinbase.clone();
        if payout_due {
            first.leaves[MARKER_LEAF][0] = Block128::from(21u128);
            second.leaves[MARKER_LEAF][0] = Block128::from(11u128);
        } else {
            first.leaves[MARKER_LEAF][0] = Block128::from(11u128);
            second.leaves[MARKER_LEAF][0] = Block128::from(12u128);
        }

        let mut builder = FieldR1csBuilder::new();
        let raw = [coinbase, first, second]
            .iter()
            .map(|body| SpineInputsTrace::alloc(&mut builder, body))
            .collect::<Vec<_>>();
        let selector = alloc_block(&mut builder, Block128::from(u128::from(payout_due)));
        let selector_square = mul(&mut builder, &selector, &selector);
        pin_eq(&mut builder, &selector_square, &selector);
        let ghost_native =
            noid_gkr::spine_statement::spine_inputs_from_body(&noid_gkr::ghost_tx::ghost_tx_body());
        let ghost = constant_spine_inputs_trace(&ghost_native);
        let payout = select_spine_inputs_trace(&mut builder, &selector, &raw[1], &ghost);
        let users = (0..2)
            .map(|index| {
                let when_due = raw.get(index + 2).unwrap_or(&ghost);
                select_spine_inputs_trace(&mut builder, &selector, when_due, &raw[index + 1])
            })
            .collect::<Vec<_>>();
        let markers = [
            payout.leaves[MARKER_LEAF][0].eval(builder.values()),
            users[0].leaves[MARKER_LEAF][0].eval(builder.values()),
            users[1].leaves[MARKER_LEAF][0].eval(builder.values()),
        ];
        let (matrix, witness) = builder.build();
        (matrix, witness, markers)
    }

    #[test]
    fn payout_multiplexes_one_existing_suffix_position_without_shape_growth() {
        let (ordinary, ordinary_witness, ordinary_markers) = selected_suffix_case(false);
        let (payout, payout_witness, payout_markers) = selected_suffix_case(true);
        assert!(ordinary.satisfies(&ordinary_witness));
        assert!(payout.satisfies(&payout_witness));
        assert_eq!(
            ordinary.structural_statement_digest(),
            payout.structural_statement_digest()
        );
        assert_eq!(ordinary.useful_rows, payout.useful_rows);

        let ghost =
            noid_gkr::spine_statement::spine_inputs_from_body(&noid_gkr::ghost_tx::ghost_tx_body());
        assert_eq!(
            ordinary_markers,
            [
                flat_of(ghost.leaves[MARKER_LEAF][0]),
                flat_of(Block128::from(11u128)),
                flat_of(Block128::from(12u128)),
            ]
        );
        assert_eq!(
            payout_markers,
            [
                flat_of(Block128::from(21u128)),
                flat_of(Block128::from(11u128)),
                flat_of(ghost.leaves[MARKER_LEAF][0]),
            ]
        );
    }

    fn bodies(start: &ChainAccumulator) -> Vec<SpineInputs> {
        let mut coinbase = SpineInputs {
            leaves: [[Block128::ZERO; 2]; noid_tx::body_hash::BODY_HASH_LEAVES],
        };
        coinbase.leaves[noid_tx::body_hash::TX8X2_LEAF_EPOCH_ANCHOR] =
            digest_lanes(&TEST_PARENT_BLOCK_ID);
        let mut user = SpineInputs {
            leaves: [[Block128::ZERO; 2]; noid_tx::body_hash::BODY_HASH_LEAVES],
        };
        user.leaves[noid_tx::body_hash::TX8X2_LEAF_EPOCH_ANCHOR] =
            digest_lanes(&start.epoch_anchor_id);
        let ghost =
            noid_gkr::spine_statement::spine_inputs_from_body(&noid_gkr::ghost_tx::ghost_tx_body());
        vec![coinbase, user, ghost]
    }

    fn build_relation(
        start: &ChainAccumulator,
        bodies: &[SpineInputs],
        real_users: usize,
    ) -> (noid_ivc_core::field_r1cs::FieldR1cs, Vec<F128>) {
        assert_eq!(bodies.len(), 3, "test tier has coinbase + two user slots");
        assert!(real_users <= 2);
        let mut b = FieldR1csBuilder::new();
        let start = AccumulatorWires::alloc(&mut b, start);
        let traces: Vec<_> = bodies
            .iter()
            .map(|body| SpineInputsTrace::alloc(&mut b, body))
            .collect();
        let live_bits: Vec<_> = (0..2)
            .map(|i| alloc_block(&mut b, Block128::from(u128::from(i < real_users))))
            .collect();
        for live in &live_bits {
            let square = mul(&mut b, live, live);
            pin_eq(&mut b, &square, live);
        }
        let parent_id = digest_lanes(&TEST_PARENT_BLOCK_ID).map(|lane| alloc_block(&mut b, lane));
        let ghost =
            noid_gkr::spine_statement::spine_inputs_from_body(&noid_gkr::ghost_tx::ghost_tx_body());
        let payout = constant_spine_inputs_trace(&ghost);
        bind_tx_epoch_anchors(
            &mut b,
            &parent_id,
            &start.epoch_anchor_id,
            &traces[0],
            &payout,
            &traces[1..],
            &LinExpr::zero(),
            &live_bits,
        );
        b.build()
    }

    fn satisfies(start: &ChainAccumulator, bodies: &[SpineInputs], real_users: usize) -> bool {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let (r1cs, witness) = build_relation(start, bodies, real_users);
            r1cs.satisfies(&witness)
        }))
        .unwrap_or(false)
    }

    #[test]
    fn coinbase_user_and_ghost_anchor_recombination() {
        let start = start_accumulator();
        let honest = bodies(&start);
        assert!(satisfies(&start, &honest, 1));

        for (body, leaf, lane) in [
            (0usize, noid_tx::body_hash::TX8X2_LEAF_EPOCH_ANCHOR, 0usize),
            (1, noid_tx::body_hash::TX8X2_LEAF_EPOCH_ANCHOR, 1),
            (2, noid_tx::body_hash::TX8X2_LEAF_FEE, 0),
            (2, noid_tx::body_hash::TX8X2_LEAF_EPOCH_ANCHOR, 1),
        ] {
            let mut bad = honest.clone();
            bad[body].leaves[leaf][lane] += Block128::ONE;
            assert!(
                !satisfies(&start, &bad, 1),
                "body {body} leaf {leaf} lane {lane} recombination accepted"
            );
        }
    }

    #[test]
    fn capacity_matrix_is_identical_across_real_user_counts() {
        let start = start_accumulator();
        let one_user = bodies(&start);
        let mut two_users = one_user.clone();
        two_users[2] = SpineInputs {
            leaves: [[Block128::ZERO; 2]; noid_tx::body_hash::BODY_HASH_LEAVES],
        };
        two_users[2].leaves[noid_tx::body_hash::TX8X2_LEAF_EPOCH_ANCHOR] =
            digest_lanes(&start.epoch_anchor_id);

        let (one_r1cs, one_witness) = build_relation(&start, &one_user, 1);
        let (two_r1cs, two_witness) = build_relation(&start, &two_users, 2);
        assert!(one_r1cs.satisfies(&one_witness));
        assert!(two_r1cs.satisfies(&two_witness));
        assert_eq!(one_r1cs.statement_digest(), two_r1cs.statement_digest());
        assert_eq!(one_r1cs.useful_rows, two_r1cs.useful_rows);
    }

    fn scheduled_system_anchor_satisfies(payout_anchor: [u8; 32]) -> bool {
        let start = start_accumulator();
        let mut coinbase = SpineInputs {
            leaves: [[Block128::ZERO; 2]; noid_tx::body_hash::BODY_HASH_LEAVES],
        };
        coinbase.leaves[noid_tx::body_hash::TX8X2_LEAF_EPOCH_ANCHOR] =
            digest_lanes(&TEST_PARENT_BLOCK_ID);
        let mut payout = SpineInputs {
            leaves: [[Block128::ZERO; 2]; noid_tx::body_hash::BODY_HASH_LEAVES],
        };
        payout.leaves[noid_tx::body_hash::TX8X2_LEAF_EPOCH_ANCHOR] = digest_lanes(&payout_anchor);
        let ghost =
            noid_gkr::spine_statement::spine_inputs_from_body(&noid_gkr::ghost_tx::ghost_tx_body());

        let mut b = FieldR1csBuilder::new();
        let start_w = AccumulatorWires::alloc(&mut b, &start);
        let traces = [coinbase, payout, ghost]
            .iter()
            .map(|body| SpineInputsTrace::alloc(&mut b, body))
            .collect::<Vec<_>>();
        let system_live = alloc_block(&mut b, Block128::ONE);
        let system_live_sq = mul(&mut b, &system_live, &system_live);
        pin_eq(&mut b, &system_live_sq, &system_live);
        let user_live = alloc_block(&mut b, Block128::ZERO);
        let parent_id = digest_lanes(&TEST_PARENT_BLOCK_ID).map(|lane| alloc_block(&mut b, lane));
        bind_tx_epoch_anchors(
            &mut b,
            &parent_id,
            &start_w.epoch_anchor_id,
            &traces[0],
            &traces[1],
            &traces[2..],
            &system_live,
            &[user_live],
        );
        let (r1cs, witness) = b.build();
        r1cs.satisfies(&witness)
    }

    #[test]
    fn scheduled_system_payout_anchors_to_the_direct_parent() {
        assert!(scheduled_system_anchor_satisfies(TEST_PARENT_BLOCK_ID));
        let mut wrong = TEST_PARENT_BLOCK_ID;
        wrong[0] ^= 1;
        assert!(!scheduled_system_anchor_satisfies(wrong));
    }

    #[test]
    fn b255_body_liveness_excludes_the_256th_authorization_pad() {
        let start = start_accumulator();
        let mut natives = bodies(&start);
        let ghost = natives.pop().expect("small fixture ghost");
        while natives.len() < 1 + noid_chain::consensus::params::BLOCK_MAX_USER_PAGES {
            natives.push(ghost.clone());
        }
        let mut b = FieldR1csBuilder::new();
        let start_w = AccumulatorWires::alloc(&mut b, &start);
        let traces: Vec<_> = natives
            .iter()
            .map(|body| SpineInputsTrace::alloc(&mut b, body))
            .collect();
        let auth_capacity = super::tier_auth_slot_count(
            Some(noid_chain::consensus::params::BLOCK_MAX_USER_PAGES),
            1,
        );
        assert_eq!(auth_capacity, 256);
        let live_bits: Vec<_> = (0..auth_capacity)
            .map(|i| alloc_block(&mut b, Block128::from(u128::from(i == 0))))
            .collect();
        for live in &live_bits {
            let square = mul(&mut b, live, live);
            pin_eq(&mut b, &square, live);
        }
        pin_zero(&mut b, &live_bits[255]);
        let parent_id = digest_lanes(&TEST_PARENT_BLOCK_ID).map(|lane| alloc_block(&mut b, lane));
        let payout = constant_spine_inputs_trace(&ghost);
        bind_tx_epoch_anchors(
            &mut b,
            &parent_id,
            &start_w.epoch_anchor_id,
            &traces[0],
            &payout,
            &traces[1..],
            &LinExpr::zero(),
            &live_bits[..255],
        );
        let (r1cs, witness) = b.build();
        assert!(r1cs.satisfies(&witness));
    }
}

#[cfg(test)]
mod paired_exact_state_connection_tests {
    use super::*;
    use crate::acceptance::trace::exact_state::{ExactStateRootWires, SlotLeafInputsTrace};
    use crate::acceptance::trace::region_source_binding::{
        PairedLocalExactStateCells, PairedUpperExactStateCells,
    };
    use noid_ivc_core::field_r1cs::FieldR1cs;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Fault {
        None,
        LocalEntry,
        LocalDirection,
        LocalChain,
        UpperEntry,
        UpperDirection,
        UpperEndpoint,
    }

    fn pair(b: &mut FieldR1csBuilder, values: [u128; 2]) -> [LinExpr; 2] {
        std::array::from_fn(|lane| alloc_block(b, Block128::from(values[lane])))
    }

    fn directions(b: &mut FieldR1csBuilder, bits: u16) -> [LinExpr; 16] {
        std::array::from_fn(|bit| alloc_block(b, Block128::from(u128::from((bits >> bit) & 1))))
    }

    fn spend_action(
        b: &mut FieldR1csBuilder,
        slot: u32,
        value: u128,
        owner: [u128; 2],
    ) -> ActionRowTrace {
        ActionRowTrace {
            live: LinExpr::from_wire(b.alloc_bool(true)),
            slot_index: alloc_block(b, Block128::from(slot as u128)),
            value: alloc_block(b, Block128::from(value)),
            owner: pair(b, owner),
            is_mint: LinExpr::zero(),
        }
    }

    fn leaf(
        b: &mut FieldR1csBuilder,
        value: u128,
        owner: [u128; 2],
        expected: [u128; 2],
    ) -> SlotLeafInputsTrace {
        SlotLeafInputsTrace {
            packed_value: alloc_block(b, Block128::from(value)),
            owner_hi: alloc_block(b, Block128::from(owner[0])),
            owner_lo: alloc_block(b, Block128::from(owner[1])),
            expected_leaf: pair(b, expected),
        }
    }

    fn drive_relation(b: &mut FieldR1csBuilder, fault: Fault) {
        // Both live slots belong to segment zero.  Using the real action
        // compactor gives this isolated connection test constrained slot bits
        // and adjacent-MSB metadata instead of trusting hand-written hints.
        let source = [
            spend_action(b, 5, 71, [81, 82]),
            spend_action(b, 9, 73, [83, 84]),
        ];
        let actions = compact_action_rows(b, &source, source.len());

        // The leaf hash outputs are deliberately arbitrary: this test targets
        // only the connection layer, while the region independently proves
        // the hash walks.  The semantic preimages still satisfy the two spend
        // transitions (old body value/owner, new canonical empty slot).
        let old_leaves = [
            leaf(b, 71, [81, 82], [11, 12]),
            leaf(b, 73, [83, 84], [13, 14]),
        ];
        let new_leaves = [leaf(b, 0, [0, 0], [21, 22]), leaf(b, 0, [0, 0], [23, 24])];
        let roots = ExactStateRootWires {
            old_root: pair(b, [901, 902]),
            new_root: pair(b, [951, 952]),
            active_depth: 24,
        };
        let exact_state = ExactStateSlotWires {
            slot_leaves: old_leaves.into_iter().chain(new_leaves).collect(),
            roots,
        };

        let mut first_old_entry = [11, 12];
        if fault == Fault::LocalEntry {
            first_old_entry[0] += 1;
        }
        let mut first_directions = 5u16;
        if fault == Fault::LocalDirection {
            first_directions ^= 1;
        }
        let mut first_after = [201, 202];
        if fault == Fault::LocalChain {
            first_after[0] += 1;
        }
        let local = vec![
            PairedLocalExactStateCells {
                old_entry: pair(b, first_old_entry),
                new_entry: pair(b, [21, 22]),
                old_root: pair(b, [101, 102]),
                new_root: pair(b, first_after),
                directions: directions(b, first_directions),
            },
            PairedLocalExactStateCells {
                old_entry: pair(b, [13, 14]),
                new_entry: pair(b, [23, 24]),
                old_root: pair(b, [201, 202]),
                new_root: pair(b, [301, 302]),
                directions: directions(b, 9),
            },
        ];

        let mut upper_old_entry = [101, 102];
        if fault == Fault::UpperEntry {
            upper_old_entry[0] += 1;
        }
        let upper_directions = if fault == Fault::UpperDirection { 1 } else { 0 };
        let old_roots = std::array::from_fn(|level| {
            if level == 7 {
                pair(b, [901, 902])
            } else {
                pair(b, [1_000 + 2 * level as u128, 1_001 + 2 * level as u128])
            }
        });
        let new_roots = std::array::from_fn(|level| {
            if level == 7 {
                let mut endpoint = [951, 952];
                if fault == Fault::UpperEndpoint {
                    endpoint[0] += 1;
                }
                pair(b, endpoint)
            } else {
                pair(b, [2_000 + 2 * level as u128, 2_001 + 2 * level as u128])
            }
        });
        let paired = PairedExactStateCells {
            local,
            upper: vec![PairedUpperExactStateCells {
                old_entry: pair(b, upper_old_entry),
                new_entry: pair(b, [301, 302]),
                old_roots,
                new_roots,
                directions: directions(b, upper_directions),
            }],
        };

        let depth_value = alloc_block(b, Block128::from(24u128));
        let child_depth = StateDepthTrace::bind(b, &depth_value);
        bind_paired_exact_state_transition(b, &actions, &exact_state, &paired, &child_depth);
    }

    fn full_case(fault: Fault) -> (FieldR1cs, Vec<F128>) {
        let mut b = FieldR1csBuilder::new();
        drive_relation(&mut b, fault);
        b.build()
    }

    fn witness_case(fault: Fault) -> (usize, Vec<F128>) {
        let mut b = FieldR1csBuilder::new_witness_only();
        drive_relation(&mut b, fault);
        b.build_witness_only()
    }

    #[test]
    fn paired_exact_state_connection_layer_rejects_every_broken_cross_link() {
        let (r1cs, honest_full) = full_case(Fault::None);
        assert!(r1cs.satisfies(&honest_full), "honest connection fixture");

        let (honest_wires, honest_witness) = witness_case(Fault::None);
        assert_eq!(honest_wires, r1cs.useful_rows, "honest wire-count parity");
        assert_eq!(honest_witness, honest_full, "honest witness-only parity");
        assert!(r1cs.satisfies(&honest_witness));

        for fault in [
            Fault::LocalEntry,
            Fault::LocalDirection,
            Fault::LocalChain,
            Fault::UpperEntry,
            Fault::UpperDirection,
            Fault::UpperEndpoint,
        ] {
            let (wire_count, witness) = witness_case(fault);
            assert_eq!(
                wire_count, r1cs.useful_rows,
                "{fault:?} changed the matrix wire count"
            );
            assert_eq!(
                witness.len(),
                honest_full.len(),
                "{fault:?} changed the padded witness length"
            );
            assert!(
                !r1cs.satisfies(&witness),
                "{fault:?} cross-link mutation was accepted"
            );
        }
    }
}

#[cfg(test)]
mod object_execution_tests {
    use super::*;
    use noid_poseidon2b::primitives::Address;
    use noid_tx::{
        experimental_object::{transaction_contexts, ObjectOpening, ObjectRules},
        output_bitmap_bit, TxBody, TxInput, TxOutput, TxPage, PAGED_SPEND_CONTRACT_BIT,
        PAGED_SPEND_END_BIT, PAGED_SPEND_START_BIT, PAGED_SPEND_TERMINAL_BIT,
    };

    fn object() -> ObjectOpening {
        ObjectOpening {
            program: noid_tx::experimental_object::integer_program::EMPTY_PROGRAM,
            state: Block128(7),
            claim_authority: Address([1; 32]),
            recovery_authority: Address([2; 32]),
            deadline: 50,
            claim_recipient: Address([3; 32]),
            recovery_recipient: Address([4; 32]),
            rules: ObjectRules {
                max_fee: 100,
                min_retained: 9_400,
                max_payout: 500,
                modes: 15,
            },
        }
    }

    fn page(
        o: &ObjectOpening,
        height: u64,
        terminal: bool,
        fee: u64,
        retained: u64,
        payout: u64,
    ) -> TxPage {
        let mut inputs = [TxInput::dummy(); 8];
        inputs[0] = TxInput {
            slot_index: 1,
            amount: fee
                .checked_add(retained)
                .unwrap()
                .checked_add(payout)
                .unwrap(),
            creation_id: 3,
        };
        let mut body = TxBody {
            epoch_anchor: [5; 32],
            fee,
            input_owner: o.root(),
            inputs,
            outputs: [
                TxOutput {
                    slot_index: 2,
                    amount: retained,
                    owner: Address([0; 32]),
                },
                if payout == 0 {
                    TxOutput::dummy()
                } else {
                    TxOutput {
                        slot_index: 3,
                        amount: payout,
                        owner: o.recipient_at(height),
                    }
                },
            ],
            validity_bitmap: 1
                | output_bitmap_bit(0)
                | PAGED_SPEND_START_BIT
                | PAGED_SPEND_END_BIT
                | PAGED_SPEND_CONTRACT_BIT
                | if terminal {
                    PAGED_SPEND_TERMINAL_BIT
                } else {
                    0
                }
                | if payout != 0 { output_bitmap_bit(1) } else { 0 },
            is_coinbase: false,
        };
        body.outputs[0].owner = if terminal {
            o.recipient_at(height)
        } else {
            o.successor(o.execute(&body, height).unwrap_or(Block128(0)))
                .root()
        };
        TxPage { body }
    }

    // Isolated execution/policy component. Full source-binding tests separately
    // authenticate these opening wires through the Meta-A object commitment.
    fn trace(o: &ObjectOpening, page: &TxPage, height: u64, bad_next: bool) -> (bool, [u8; 32]) {
        trace_with_next(o, page, height, bad_next, None)
    }

    fn trace_with_next(
        o: &ObjectOpening,
        page: &TxPage,
        height: u64,
        bad_next: bool,
        next_override: Option<Block128>,
    ) -> (bool, [u8; 32]) {
        let native_height = height;
        let mut b = FieldR1csBuilder::new();
        let height = alloc_block(&mut b, Block128(height as u128));
        let height: [Wire; 64] = range_check_bits(&mut b, &height, 64).try_into().unwrap();
        let mut spines = Vec::new();
        let mut surfaces = Vec::new();
        let mut contracts = Vec::new();
        for index in 0..1 {
            let active = index == 0;
            let ghost = noid_gkr::ghost_tx::ghost_tx_body();
            let body = if active { &page.body } else { &ghost };
            let spine = SpineInputsTrace::alloc(
                &mut b,
                &noid_gkr::spine_statement::spine_inputs_from_body(body),
            );
            let tx_live = alloc_block(&mut b, Block128(u128::from(active)));
            let surface = bind_user_action_surface_for_profile(&mut b, &spine, &tx_live, true);
            let mut field =
                |value: Block128| alloc_block(&mut b, if active { value } else { Block128(0) });
            let next = next_override
                .unwrap_or_else(|| o.execute(body, native_height).unwrap_or(Block128(0)))
                + Block128(u128::from(bad_next && active));
            contracts.push(V2ContractView {
                live: surface.contract.clone(),
                terminal: surface.terminal.clone(),
                program_w: o.program.map(|pair| pair.map(&mut field)),
                current_w: field(o.state),
                next_w: field(next),
                controller_w: o.claim_authority.as_fields().map(&mut field),
                refund_authority_w: o.recovery_authority.as_fields().map(&mut field),
                contexts_w: transaction_contexts(body).map(&mut field),
                deadline_w: field(Block128(o.deadline as u128)),
                claim_recipient_w: o.claim_recipient.as_fields().map(&mut field),
                refund_recipient_w: o.recovery_recipient.as_fields().map(&mut field),
                rules_w: o.rules.fields().map(&mut field),
            });
            spines.push(spine);
            surfaces.push(surface);
        }
        bind_v2_contract_partition(&mut b, &surfaces, &contracts, true);
        let policy = bind_v2_contract_policy(&mut b, &contracts, &height);
        bind_v2_contract_execution(&mut b, &spines, &surfaces, &contracts, &policy, false);
        let (matrix, witness) = b.build();
        (
            matrix.satisfies(&witness),
            matrix.structural_statement_digest(),
        )
    }

    #[test]
    fn spending_rules_match_native_checks_without_witness_dependent_rows() {
        let mut digest = None;
        let mut check = |o: &ObjectOpening, p: TxPage, height| {
            let expected = o.check_call(&p, height).is_ok();
            let (satisfied, actual) = trace(o, &p, height, false);
            assert_eq!(
                satisfied, expected,
                "height={height}, rules={:?}, fee={}",
                o.rules, p.body.fee
            );
            assert!(digest.is_none_or(|previous| previous == actual));
            digest = Some(actual);
        };
        for modes in 0..=31 {
            let mut o = object();
            o.rules.modes = modes;
            for height in [49, 50] {
                check(&o, page(&o, height, false, 100, 9_400, 500), height);
                check(&o, page(&o, height, true, 100, 9_900, 0), height);
            }
        }
        let o = object();
        for fee in [99, 100, 101] {
            check(&o, page(&o, 49, false, fee, 9_400, 500), 49);
        }
        for retained in [9_399, 9_400, 9_401] {
            check(&o, page(&o, 49, false, 100, retained, 500), 49);
        }
        for payout in [499, 500, 501] {
            check(&o, page(&o, 49, false, 100, 9_400, payout), 49);
        }
        for unrestricted in [false, true] {
            let mut o = object();
            o.rules.modes |= if unrestricted { 16 } else { 0 };
            let mut p = page(&o, 49, false, 100, 9_400, 500);
            p.body.outputs[1].owner = Address([8; 32]);
            check(&o, p, 49);
        }
        for amount in [1u64 << 63, u64::MAX - 300] {
            let mut o = object();
            o.rules.max_fee = amount;
            check(&o, page(&o, 49, true, amount, 100, 0), 49);
            check(&o, page(&o, 49, true, amount + 1, 100, 0), 49);
            let mut o = object();
            o.rules.max_payout = amount;
            o.rules.min_retained = 100;
            check(&o, page(&o, 49, false, 100, 100, amount), 49);
            check(&o, page(&o, 49, false, 100, 100, amount + 1), 49);
        }
        let mut invalid = object();
        invalid.rules.modes = 32;
        check(&invalid, page(&invalid, 49, false, 100, 9_400, 500), 49);
    }

    #[test]
    fn integer_instructions_and_assertion_failures_are_constrained() {
        use noid_tx::experimental_object::integer_program::{
            Instruction, Opcode, Operand, Register,
        };
        let mut digest = None;
        for opcode in Opcode::ALL {
            let mut o = object();
            o.program[2] = Instruction::new(
                opcode,
                Register::State0,
                Operand::State0,
                Operand::Immediate,
                7,
            )
            .to_fields();
            let p = page(&o, 49, false, 100, 9_400, 500);
            let (satisfied, actual) = trace(&o, &p, 49, false);
            assert!(satisfied, "opcode={opcode:?}");
            assert!(o.check_call(&p, 49).is_ok());
            assert!(
                !trace(&o, &p, 49, true).0,
                "unbound next state at opcode={opcode:?}"
            );
            assert!(digest.is_none_or(|previous| previous == actual));
            digest = Some(actual);
            if matches!(opcode, Opcode::AssertEqual | Opcode::AssertLessOrEqual) {
                o.program[2][1] = Block128(6);
                let p = page(&o, 49, false, 100, 9_400, 500);
                assert!(o.check_call(&p, 49).is_err());
                assert!(!trace(&o, &p, 49, false).0);
            }
        }
        let mut o = object();
        o.program[2][0] = Block128(15);
        let p = page(&o, 49, false, 100, 9_400, 500);
        assert!(!trace(&o, &p, 49, false).0);
        assert!(o.check_call(&p, 49).is_err());
    }

    #[test]
    fn every_integer_body_operand_matches_native_and_height_cannot_be_substituted() {
        use noid_tx::experimental_object::integer_program::{
            Instruction, Opcode, Operand, Register,
        };
        let mut digest = None;
        for operand in Operand::ALL {
            let mut o = object();
            o.program[0] =
                Instruction::new(Opcode::Move, Register::State0, operand, Operand::Zero, 19)
                    .to_fields();
            let p = page(&o, 49, false, 100, 9_400, 500);
            let (valid, shape) = trace(&o, &p, 49, false);
            assert!(valid, "{operand:?}");
            assert!(digest.is_none_or(|value| value == shape));
            digest = Some(shape);
            assert!(!trace(&o, &p, 49, true).0, "unbound result for {operand:?}");
            if operand == Operand::Height {
                let forged = o.execute(&p.body, 48).unwrap();
                assert!(!trace_with_next(&o, &p, 49, false, Some(forged)).0);
            }
        }
    }

    #[test]
    fn scheduled_templates_share_one_relation_and_enforce_claims_and_recovery() {
        use noid_tx::experimental_object::{applications::*, integer_program::pack_state};
        let owner = Address([1; 32]);
        let mut budget = period_budget_wallet(
            owner,
            Address([2; 32]),
            None,
            PeriodBudget {
                start_height: 100,
                period_blocks: 10,
                budget: 100,
                recover_at: 180,
                max_fee: 5,
                max_payout: 100,
                min_retained: 10,
            },
        )
        .unwrap();
        // A preceding call spent the entire budget; only the reset may restore it.
        budget.state = pack_state([0, 110]);
        let recurring = recurring_payment(
            owner,
            owner,
            RecurringPayment {
                first_due_height: 110,
                period_blocks: 10,
                payment: 50,
                recover_at: 180,
                max_fee: 5,
            },
        )
        .unwrap();
        let vesting = tranche_vesting(
            owner,
            TrancheVesting {
                first_unlock_height: 110,
                period_blocks: 10,
                tranche_amount: 50,
                mature_at: 180,
                max_fee: 5,
            },
        )
        .unwrap();
        let mut digest = None;
        for o in [budget, recurring, vesting] {
            for (height, terminal, payout, valid) in [
                (99, false, 50, false),
                (109, false, 50, false),
                (110, false, 50, true),
                (179, false, 50, true),
                (179, true, 0, false),
                (180, true, 0, true),
                (180, false, 50, false),
            ] {
                let p = page(&o, height, terminal, 5, 9_400, payout);
                assert_eq!(o.check_call(&p, height).is_ok(), valid);
                let (satisfied, shape) = trace(&o, &p, height, false);
                assert_eq!(satisfied, valid, "height={height}, terminal={terminal}");
                assert!(digest.is_none_or(|value| value == shape));
                digest = Some(shape);
            }
        }
    }
}

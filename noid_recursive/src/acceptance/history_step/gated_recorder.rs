// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Parent-arm recorder for the base-selectable HistoryStep relation.
//!
//! It is transcript-identical to `FsChannelUnionRecorder`.  The sole local
//! difference is that the BaseFold grind range equality goes through the
//! recursive trace's scoped `pin_eq`, so `live = 0` gates that verifier
//! rejection together with every other parent-arm rejection.  No transcript
//! byte, proof parameter, or primitive is changed.

use noid_ivc_core::challenger::{
    fs_c1_lane_iv_flat, fs_op_lane, fs_pack_bytes_lanes, fs_pad_lane_flat, FS_KIND_SCALAR,
    FS_KIND_SLICE, FS_KIND_WIDE_SCALAR, FS_KIND_WIDE_SLICE, FS_OP_BYTES, FS_OP_DOMAIN, FS_OP_LABEL,
    FS_OP_OBSERVE, FS_OP_POW, FS_OP_SQUEEZE,
};
use noid_ivc_core::field::F128;
use noid_ivc_core::field_circuit::{
    f128_from_u128, f128_to_u128, ExtExpr, FieldR1csBuilder, FsChannelOps, LinExpr, RecordedChannel,
};
use noid_poseidon2b::native::permutation::STATE_SIZE;

use super::super::trace::pin_eq;

pub(super) struct BaseSelectableParentRecorder {
    state: [F128; STATE_SIZE],
    buffered: Option<F128>,
    pending: Option<F128>,
    cur_absorb: Vec<Option<u128>>,
    ops: Vec<noid_ivc_core::deep_chain::schedule::TranscriptOp>,
    data_wires: Vec<LinExpr>,
    data_flat: Vec<F128>,
    challenge_wires: Vec<LinExpr>,
    perms: usize,
    c1: bool,
}

impl BaseSelectableParentRecorder {
    pub(super) fn new_c1(domain: &[u8]) -> Self {
        Self::with_profile(domain, fs_c1_lane_iv_flat(), true)
    }

    fn with_profile(domain: &[u8], [iv0, iv1]: [F128; 2], c1: bool) -> Self {
        let mut recorder = Self {
            state: [F128::ZERO, F128::ZERO, iv0, iv1],
            buffered: None,
            pending: None,
            cur_absorb: Vec::new(),
            ops: Vec::new(),
            data_wires: Vec::new(),
            data_flat: Vec::new(),
            challenge_wires: Vec::new(),
            perms: 0,
            c1,
        };
        recorder.absorb_const(fs_op_lane(FS_OP_DOMAIN, 0, domain.len() as u64));
        for lane in fs_pack_bytes_lanes(domain) {
            recorder.absorb_const(lane);
        }
        recorder
    }

    fn flat_bits(value: F128) -> u128 {
        (value.lo as u128) | ((value.hi as u128) << 64)
    }

    fn permute(&mut self) {
        let mut lanes: [u128; STATE_SIZE] =
            std::array::from_fn(|index| Self::flat_bits(self.state[index]));
        noid_poseidon2b::native::permutation::permute_flat_u128(&mut lanes);
        self.state = std::array::from_fn(|index| F128 {
            lo: lanes[index] as u64,
            hi: (lanes[index] >> 64) as u64,
        });
        self.perms += 1;
    }

    fn absorb_native(&mut self, value: F128) {
        self.pending = None;
        if let Some(first) = self.buffered.take() {
            self.state[0] += first;
            self.state[1] += value;
            self.permute();
        } else {
            self.buffered = Some(value);
        }
    }

    fn absorb_const(&mut self, value: F128) {
        self.cur_absorb
            .push(Some(noid_core::hardware::flat_to_tower_u128(
                Self::flat_bits(value),
            )));
        self.absorb_native(value);
    }

    fn absorb_expr(&mut self, builder: &FieldR1csBuilder, expression: &LinExpr) {
        if expression.is_const() {
            self.absorb_const(expression.constant);
        } else {
            let value = expression.eval(builder.values());
            self.cur_absorb.push(None);
            self.data_wires.push(expression.clone());
            self.data_flat.push(value);
            self.absorb_native(value);
        }
    }

    fn close_absorb(&mut self) {
        if !self.cur_absorb.is_empty() {
            self.ops
                .push(noid_ivc_core::deep_chain::schedule::TranscriptOp::Absorb(
                    std::mem::take(&mut self.cur_absorb),
                ));
        }
    }

    fn squeeze_native(&mut self) -> F128 {
        if let Some(pending) = self.pending.take() {
            return pending;
        }
        if let Some(first) = self.buffered.take() {
            self.state[0] += first;
            self.state[1] += fs_pad_lane_flat();
            self.permute();
        }
        let out = self.state[0];
        self.pending = Some(self.state[1]);
        self.permute();
        out
    }

    fn squeeze(&mut self, builder: &mut FieldR1csBuilder) -> LinExpr {
        let value = self.squeeze_native();
        let wire = LinExpr::from_wire(builder.alloc_f128(value));
        self.challenge_wires.push(wire.clone());
        wire
    }

    fn gated_decompose_bits_le(
        builder: &mut FieldR1csBuilder,
        expression: &LinExpr,
        n_bits: usize,
    ) {
        assert!(n_bits <= 128);
        let value = f128_to_u128(expression.eval(builder.values()));
        let bits = (0..n_bits)
            .map(|bit| builder.alloc_bool((value >> bit) & 1 == 1))
            .collect::<Vec<_>>();
        let reconstructed =
            bits.into_iter()
                .enumerate()
                .fold(LinExpr::zero(), |sum, (bit, wire)| {
                    sum.add(&LinExpr::from_wire(wire).scale(f128_from_u128(1u128 << bit)))
                });
        pin_eq(builder, &reconstructed, expression);
    }

    pub(super) fn select_prefix(
        builder: &mut FieldR1csBuilder,
        selector: &LinExpr,
        zero: Self,
        one: Self,
    ) -> Option<Self> {
        if zero.ops != one.ops
            || zero.cur_absorb != one.cur_absorb
            || zero.data_wires.len() != one.data_wires.len()
            || zero.challenge_wires.len() != one.challenge_wires.len()
            || zero.buffered.is_some() != one.buffered.is_some()
            || zero.pending.is_some() != one.pending.is_some()
            || zero.perms != one.perms
            || zero.c1 != one.c1
        {
            return None;
        }
        let select_one = match selector.eval(builder.values()) {
            F128::ZERO => false,
            F128::ONE => true,
            _ => return None,
        };
        let boolean =
            crate::acceptance::trace::mul(builder, selector, &selector.add_const(F128::ONE));
        pin_eq(builder, &boolean, &LinExpr::zero());
        let choose = |builder: &mut FieldR1csBuilder, left: &LinExpr, right: &LinExpr| {
            if left == right {
                return left.clone();
            }
            let delta = crate::acceptance::trace::mul(builder, selector, &left.add(right));
            left.add(&delta)
        };
        let data_wires = zero
            .data_wires
            .iter()
            .zip(&one.data_wires)
            .map(|(left, right)| choose(builder, left, right))
            .collect();
        let challenge_wires = zero
            .challenge_wires
            .iter()
            .zip(&one.challenge_wires)
            .map(|(left, right)| choose(builder, left, right))
            .collect();
        let selected = if select_one { &one } else { &zero };
        Some(Self {
            state: selected.state,
            buffered: selected.buffered,
            pending: selected.pending,
            data_flat: selected.data_flat.clone(),
            perms: selected.perms,
            c1: selected.c1,
            cur_absorb: zero.cur_absorb,
            ops: zero.ops,
            data_wires,
            challenge_wires,
        })
    }

    pub(super) fn finish(mut self) -> RecordedChannel {
        self.close_absorb();
        RecordedChannel {
            ops: self.ops,
            data_wires: self.data_wires,
            data_flat: self.data_flat,
            challenge_wires: self.challenge_wires,
            post_state: self.state,
            perms: self.perms,
        }
    }
}

impl FsChannelOps for BaseSelectableParentRecorder {
    fn observe_label(&mut self, _builder: &mut FieldR1csBuilder, label: &[u8]) {
        self.absorb_const(fs_op_lane(FS_OP_LABEL, 0, label.len() as u64));
        for lane in fs_pack_bytes_lanes(label) {
            self.absorb_const(lane);
        }
    }

    fn observe_f128(&mut self, builder: &mut FieldR1csBuilder, value: &LinExpr) {
        self.absorb_const(fs_op_lane(FS_OP_OBSERVE, FS_KIND_SCALAR, 0));
        self.absorb_expr(builder, value);
    }

    fn observe_f128_slice(&mut self, builder: &mut FieldR1csBuilder, values: &[LinExpr]) {
        self.absorb_const(fs_op_lane(
            FS_OP_OBSERVE,
            FS_KIND_SLICE,
            values.len() as u64,
        ));
        for value in values {
            self.absorb_expr(builder, value);
        }
    }

    fn observe_f256(&mut self, builder: &mut FieldR1csBuilder, value: &ExtExpr) {
        assert!(self.c1, "wide transcript operation requires new_c1");
        self.absorb_const(fs_op_lane(FS_OP_OBSERVE, FS_KIND_WIDE_SCALAR, 0));
        self.absorb_expr(builder, &value.lo);
        self.absorb_expr(builder, &value.hi);
    }

    fn observe_f256_slice(&mut self, builder: &mut FieldR1csBuilder, values: &[ExtExpr]) {
        assert!(self.c1, "wide transcript operation requires new_c1");
        self.absorb_const(fs_op_lane(
            FS_OP_OBSERVE,
            FS_KIND_WIDE_SLICE,
            values.len() as u64,
        ));
        for value in values {
            self.absorb_expr(builder, &value.lo);
            self.absorb_expr(builder, &value.hi);
        }
    }

    fn sample_f128(&mut self, builder: &mut FieldR1csBuilder) -> LinExpr {
        self.absorb_const(fs_op_lane(FS_OP_SQUEEZE, FS_KIND_SCALAR, 0));
        self.close_absorb();
        self.ops
            .push(noid_ivc_core::deep_chain::schedule::TranscriptOp::Squeeze(
                1,
            ));
        self.squeeze(builder)
    }

    fn sample_f128_vec(&mut self, builder: &mut FieldR1csBuilder, n: usize) -> Vec<LinExpr> {
        self.absorb_const(fs_op_lane(FS_OP_SQUEEZE, FS_KIND_SLICE, n as u64));
        self.close_absorb();
        self.ops
            .push(noid_ivc_core::deep_chain::schedule::TranscriptOp::Squeeze(
                n,
            ));
        (0..n).map(|_| self.squeeze(builder)).collect()
    }

    fn sample_f256(&mut self, builder: &mut FieldR1csBuilder) -> ExtExpr {
        assert!(self.c1, "wide transcript operation requires new_c1");
        self.absorb_const(fs_op_lane(FS_OP_SQUEEZE, FS_KIND_WIDE_SCALAR, 0));
        self.close_absorb();
        self.ops
            .push(noid_ivc_core::deep_chain::schedule::TranscriptOp::Squeeze(
                2,
            ));
        let lo = self.squeeze(builder);
        let raw_hi = self.squeeze(builder);
        builder.c1_challenge_from_raw(lo, raw_hi)
    }

    fn sample_f256_vec(&mut self, builder: &mut FieldR1csBuilder, n: usize) -> Vec<ExtExpr> {
        assert!(self.c1, "wide transcript operation requires new_c1");
        self.absorb_const(fs_op_lane(FS_OP_SQUEEZE, FS_KIND_WIDE_SLICE, n as u64));
        self.close_absorb();
        self.ops
            .push(noid_ivc_core::deep_chain::schedule::TranscriptOp::Squeeze(
                2 * n,
            ));
        (0..n)
            .map(|_| {
                let lo = self.squeeze(builder);
                let raw_hi = self.squeeze(builder);
                builder.c1_challenge_from_raw(lo, raw_hi)
            })
            .collect()
    }

    fn verify_pow(&mut self, builder: &mut FieldR1csBuilder, nonce: &LinExpr, bits: u32) {
        assert!(bits <= 64, "leading-zero window limited to the top limb");
        self.absorb_const(fs_op_lane(FS_OP_POW, 0, bits as u64));
        self.absorb_expr(builder, nonce);
        self.absorb_const(fs_op_lane(FS_OP_SQUEEZE, FS_KIND_SCALAR, 0));
        self.close_absorb();
        self.ops
            .push(noid_ivc_core::deep_chain::schedule::TranscriptOp::Squeeze(
                1,
            ));
        let challenge = self.squeeze(builder);
        if bits > 0 {
            Self::gated_decompose_bits_le(builder, &challenge, 128 - bits as usize);
        } else {
            Self::gated_decompose_bits_le(builder, nonce, 0);
        }
    }

    fn observe_bytes_const(&mut self, _builder: &mut FieldR1csBuilder, bytes: &[u8]) {
        self.absorb_const(fs_op_lane(FS_OP_BYTES, 0, bytes.len() as u64));
        for lane in fs_pack_bytes_lanes(bytes) {
            self.absorb_const(lane);
        }
    }

    fn observe_lanes(&mut self, builder: &mut FieldR1csBuilder, byte_len: u64, lanes: &[LinExpr]) {
        assert_eq!(lanes.len() as u64, byte_len.div_ceil(16));
        self.absorb_const(fs_op_lane(FS_OP_BYTES, 0, byte_len));
        for lane in lanes {
            self.absorb_expr(builder, lane);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_ivc_core::field::F256;
    use noid_ivc_core::field_circuit::FsChannelUnionRecorder;

    fn exercise_c1(
        builder: &mut FieldR1csBuilder,
        channel: &mut impl FsChannelOps,
        values: &[ExtExpr],
    ) -> Vec<F256> {
        channel.observe_label(builder, b"parent-recorder-c1-test");
        channel.observe_f256(builder, &values[0]);
        channel.observe_f256_slice(builder, &values[1..]);
        let mut sampled = vec![channel.sample_f256(builder).eval(builder.values())];
        sampled.extend(
            channel
                .sample_f256_vec(builder, 3)
                .iter()
                .map(|value| value.eval(builder.values())),
        );
        let _query_seed = channel.sample_f128_vec(builder, 23);
        sampled
    }

    #[test]
    fn selectable_parent_c1_recorder_matches_union_recorder() {
        const DOMAIN: &[u8] = b"parent-recorder-c1";
        let native_values = [
            F256::new(F128::new(1, 2), F128::new(3, 4)),
            F256::new(F128::new(5, 6), F128::new(7, 8)),
            F256::new(F128::new(9, 10), F128::new(11, 12)),
        ];

        let mut selectable_builder = FieldR1csBuilder::new();
        let selectable_values = native_values.map(|value| {
            ExtExpr::new(
                LinExpr::from_wire(selectable_builder.alloc_f128(value.lo)),
                LinExpr::from_wire(selectable_builder.alloc_f128(value.hi)),
            )
        });
        let mut selectable =
            BaseSelectableParentRecorder::with_profile(DOMAIN, fs_c1_lane_iv_flat(), true);
        let selectable_samples =
            exercise_c1(&mut selectable_builder, &mut selectable, &selectable_values);
        let selectable_recording = selectable.finish();

        let mut union_builder = FieldR1csBuilder::new();
        let union_values = native_values.map(|value| {
            ExtExpr::new(
                LinExpr::from_wire(union_builder.alloc_f128(value.lo)),
                LinExpr::from_wire(union_builder.alloc_f128(value.hi)),
            )
        });
        let mut union = FsChannelUnionRecorder::new_c1(DOMAIN);
        let union_samples = exercise_c1(&mut union_builder, &mut union, &union_values);
        let union_recording = union.finish();

        assert_eq!(selectable_samples, union_samples);
        assert_eq!(selectable_recording.ops, union_recording.ops);
        assert_eq!(selectable_recording.data_wires, union_recording.data_wires);
        assert_eq!(selectable_recording.data_flat, union_recording.data_flat);
        assert_eq!(
            selectable_recording.challenge_wires,
            union_recording.challenge_wires
        );
        assert_eq!(selectable_recording.post_state, union_recording.post_state);
        assert_eq!(selectable_recording.perms, union_recording.perms);

        let (selectable_r1cs, selectable_witness) = selectable_builder.build();
        let (union_r1cs, union_witness) = union_builder.build();
        assert_eq!(
            selectable_r1cs.structural_statement_digest(),
            union_r1cs.structural_statement_digest()
        );
        assert_eq!(selectable_witness, union_witness);
        assert!(selectable_r1cs.satisfies(&selectable_witness));
    }
}

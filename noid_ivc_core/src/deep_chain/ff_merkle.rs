// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Feed-forward Merkle path family: authentication chains over
//! 1-PERMUTATION compress nodes (`compress_flat_feed_forward_with_tag`) —
//! the node shape of the capsule PCS trees and the proof-core PCS Merkle.
//!
//! One slot per node (the 2-permutation sponge family needs two). Node `k`
//! of a path with leaf index bits `d_k`:
//!
//! ```text
//! a = d ? sibling : carried          -- the feed-forward half
//! b = d ? carried : sibling
//! S_in  = [a0, a1, b0 + iv0, b1 + iv1]      (iv = TAG capacity, a pattern)
//! digest = S_out[0..2] + a                  (the XOR feed-forward)
//! carried(k+1) = digest(k); carried(0) = the entry digest
//! ```
//!
//! Committed cells per node slot: `CR` (the carried-IN digest, 2 lanes —
//! in the caller's shared entry columns), `SIB` (2), `D` (1), plus the
//! walk's shared output state `C0..C3`. The recurrence terminates because
//! `CR` is committed: with `mix = CR + D·(CR + SIB)` (`= a`),
//!
//! - substitution (per-slot `S_in`), NODE slots on top of the ghost
//!   carry `raw = C(w-1)`:
//!   `raw_i     = mix_i`             (lanes 0, 1)
//!   `raw_{2+i} = mix_i + CR_i + SIB_i + IV_i`   (`= b_i + iv_i`)
//! - the CR-CHAIN zero-check on non-start node slots:
//!   `0 = CR_i(w) + C_i(w-1) + mix_i(w-1)` — the previous node's digest;
//! - path-start entry binding is a plain cell pin into `CR(start)`;
//! - when the dyadic stride has a spare tail slot, `NODENS` extends one slot
//!   past the final node and the chain writes that recomputed digest into
//!   `CR(root-copy)`. The caller can then pin the transcript-observed root
//!   directly to one committed cell instead of rebuilding the final mix.
//!
//! Slot layout: path `p` occupies `[p·stride, p·stride + depth)` with
//! `stride = depth.next_power_of_two()`; stride tails and slots past the
//! last path are ghost permutations carrying the state forward.

use crate::deep_chain::relations::{ColRef, FixedPattern, RelationTerm};
use crate::deep_chain::source_tree::run_perm;
use crate::field::F128;
use noid_poseidon2b::native::permutation::{MDS_FULL, STATE_SIZE};

use super::schedule::flat_of_tower_u128;

/// One feed-forward Merkle path family: `n_paths` chains of `depth` nodes.
#[derive(Clone, Copy, Debug)]
pub struct FfMerklePathFamily {
    pub depth: usize,
    pub n_paths: usize,
}

impl FfMerklePathFamily {
    pub fn stride(&self) -> usize {
        self.depth.next_power_of_two()
    }
    pub fn stride_log(&self) -> usize {
        self.stride().trailing_zeros() as usize
    }
    pub fn n_slots(&self) -> usize {
        self.n_paths * self.stride()
    }

    /// The in-stride slot used to expose the recomputed root as a committed
    /// `CR` cell. A power-of-two depth has no spare tail and retains the
    /// legacy composite-root handoff.
    pub fn root_copy_offset(&self) -> Option<usize> {
        (self.depth < self.stride()).then_some(self.depth)
    }
}

/// Column/pattern indices of one ff-Merkle family inside caller-managed
/// tables. Column order: `CR0, CR1, SIB0, SIB1, D, C0..C3`; pattern order:
/// `NODE, NODENS, START, IV0, IV1`.
#[derive(Clone, Copy, Debug)]
pub struct FfMerkleFamilyRefs {
    pub cr: [usize; 2],
    pub sib: [usize; 2],
    pub d: usize,
    pub c: [usize; STATE_SIZE],
    pub node: usize,
    pub nodens: usize,
    pub start: usize,
    pub iv: [usize; 2],
}

/// The family's fixed patterns over one stride period, in the
/// [`FfMerkleFamilyRefs`] order (`NODE, NODENS, START, IV0, IV1`).
pub fn ff_merkle_fixed_patterns(
    family: &FfMerklePathFamily,
    iv_flat: [F128; 2],
) -> Vec<FixedPattern> {
    let low_log = family.stride_log();
    let period = family.stride();
    let mut node = vec![F128::ZERO; period];
    let mut nodens = vec![F128::ZERO; period];
    let mut start = vec![F128::ZERO; period];
    let mut iv0 = vec![F128::ZERO; period];
    let mut iv1 = vec![F128::ZERO; period];
    for k in 0..family.depth {
        node[k] = F128::ONE;
        iv0[k] = iv_flat[0];
        iv1[k] = iv_flat[1];
        if k == 0 {
            start[0] = F128::ONE;
        } else {
            nodens[k] = F128::ONE;
        }
    }
    if let Some(root_copy) = family.root_copy_offset() {
        // One extra CR-chain equation exposes the final feed-forward digest.
        // NODE stays zero here, so the slot remains a ghost permutation and
        // no additional compression is introduced.
        nodens[root_copy] = F128::ONE;
    }
    vec![
        FixedPattern::new(low_log, node),
        FixedPattern::new(low_log, nodens),
        FixedPattern::new(low_log, start),
        FixedPattern::new(low_log, iv0),
        FixedPattern::new(low_log, iv1),
    ]
}

/// Substitution terms for the α-batched walk terminal claim: the NODE-slot
/// `S_in` on top of the ghost carry (the ghost `c_sh` default is supplied
/// by the caller's leg-region term; NODE slots cancel it and add the node
/// wiring).
pub fn ff_merkle_substitution_terms(refs: &FfMerkleFamilyRefs, alpha: F128) -> Vec<RelationTerm> {
    let flat = |v: u128| flat_of_tower_u128(v);
    let mut alphas = [F128::ZERO; STATE_SIZE];
    let mut p = F128::ONE;
    for a in alphas.iter_mut() {
        p = p * alpha;
        *a = p;
    }
    let m: [F128; STATE_SIZE] = std::array::from_fn(|j| {
        let mut acc = F128::ZERO;
        for e in 0..STATE_SIZE {
            acc += alphas[e] * flat(MDS_FULL[e][j]);
        }
        acc
    });

    let mut terms = Vec::new();
    let node = ColRef::Fixed(refs.node);
    for i in 0..2 {
        let cr = ColRef::Committed(refs.cr[i]);
        let sib = ColRef::Committed(refs.sib[i]);
        let d = ColRef::Committed(refs.d);
        let c_sh = ColRef::CommittedShift(refs.c[i]);
        // Lane i: cancel the ghost carry, add mix = CR + D·(CR + SIB).
        for factors in [
            vec![node, c_sh],
            vec![node, cr],
            vec![node, d, cr],
            vec![node, d, sib],
        ] {
            terms.push(RelationTerm {
                coeff: m[i],
                factors,
            });
        }
        // Lane 2+i: cancel the ghost carry, add b + iv = mix + CR + SIB + IV
        // (the CR terms cancel: mix + CR = D·(CR+SIB)).
        let j = 2 + i;
        let c_sh_j = ColRef::CommittedShift(refs.c[j]);
        for factors in [
            vec![node, c_sh_j],
            vec![node, ColRef::Committed(refs.sib[i])],
            vec![
                node,
                ColRef::Committed(refs.d),
                ColRef::Committed(refs.cr[i]),
            ],
            vec![
                node,
                ColRef::Committed(refs.d),
                ColRef::Committed(refs.sib[i]),
            ],
            vec![ColRef::Fixed(refs.iv[i])],
        ] {
            terms.push(RelationTerm {
                coeff: m[j],
                factors,
            });
        }
    }
    terms
}

/// The CR-chain zero-check terms: on every non-start node slot (and the
/// optional root-copy tail slot),
/// `0 = CR_i(w) + C_i(w-1) + CR_i(w-1) + D(w-1)·(CR_i(w-1) + SIB_i(w-1))`
/// — i.e. the carried-in digest equals the previous node's feed-forward
/// output. One relation covers both lanes via the caller's per-lane
/// weighting (`alpha` here mirrors the substitution builder's batching).
pub fn ff_merkle_chain_terms(refs: &FfMerkleFamilyRefs, alpha: F128) -> Vec<RelationTerm> {
    let mut terms = Vec::new();
    let mut w = F128::ONE;
    for i in 0..2 {
        w = w * alpha;
        let nodens = ColRef::Fixed(refs.nodens);
        let cr = ColRef::Committed(refs.cr[i]);
        let cr_sh = ColRef::CommittedShift(refs.cr[i]);
        let sib_sh = ColRef::CommittedShift(refs.sib[i]);
        let d_sh = ColRef::CommittedShift(refs.d);
        let c_sh = ColRef::CommittedShift(refs.c[i]);
        for factors in [
            vec![nodens, cr],
            vec![nodens, c_sh],
            vec![nodens, cr_sh],
            vec![nodens, d_sh, cr_sh],
            vec![nodens, d_sh, sib_sh],
        ] {
            terms.push(RelationTerm { coeff: w, factors });
        }
    }
    terms
}

/// Direction-bit booleanity on node slots: `0 = Σ eq·NODE·(D² + D)`.
pub fn ff_merkle_booleanity_terms(refs: &FfMerkleFamilyRefs) -> Vec<RelationTerm> {
    vec![
        RelationTerm {
            coeff: F128::ONE,
            factors: vec![
                ColRef::Fixed(refs.node),
                ColRef::Committed(refs.d),
                ColRef::Committed(refs.d),
            ],
        },
        RelationTerm {
            coeff: F128::ONE,
            factors: vec![ColRef::Fixed(refs.node), ColRef::Committed(refs.d)],
        },
    ]
}

/// One path's witness: entry digest, per-node sibling digests and
/// direction bits (`true` = the carried digest is the RIGHT child, i.e.
/// `a = sibling`).
pub type FfMerklePathWitness = super::schedule::MerklePathWitness;

/// Native flat-basis columns of one ff-Merkle family.
pub struct FfMerklePathColumns {
    pub cr: [Vec<F128>; 2],
    pub sib: [Vec<F128>; 2],
    pub d: Vec<F128>,
    pub c: [Vec<F128>; STATE_SIZE],
    pub s0: [Vec<F128>; STATE_SIZE],
    pub s_out: [Vec<F128>; STATE_SIZE],
    /// Per path: the recomputed root digest (`C + mix` at the last node).
    /// When [`FfMerklePathFamily::root_copy_offset`] is present, the same
    /// digest is also stored in `cr[*][p*stride + root_copy_offset]`.
    pub roots: Vec<[F128; 2]>,
}

/// Replay every path chain natively and fill the family columns.
pub fn build_ff_merkle_path_columns(
    family: &FfMerklePathFamily,
    iv_flat: [F128; 2],
    paths: &[FfMerklePathWitness],
    w_log: usize,
) -> FfMerklePathColumns {
    let w = 1usize << w_log;
    let stride = family.stride();
    assert_eq!(paths.len(), family.n_paths);
    assert!(family.n_slots() <= w, "slot domain below the family");

    let mut cr: [Vec<F128>; 2] = std::array::from_fn(|_| vec![F128::ZERO; w]);
    let mut sib: [Vec<F128>; 2] = std::array::from_fn(|_| vec![F128::ZERO; w]);
    let mut d = vec![F128::ZERO; w];
    let mut c: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; w]);
    let mut s0: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; w]);
    let mut s_out: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; w]);
    let mut roots = Vec::with_capacity(family.n_paths);

    // Witness cells: the carried digest per node is the previous node's
    // feed-forward output, so fill CR while replaying below.
    for (p, path) in paths.iter().enumerate() {
        assert_eq!(path.siblings.len(), family.depth);
        assert_eq!(path.directions.len(), family.depth);
        let base = p * stride;
        for k in 0..family.depth {
            sib[0][base + k] = path.siblings[k][0];
            sib[1][base + k] = path.siblings[k][1];
            d[base + k] = if path.directions[k] {
                F128::ONE
            } else {
                F128::ZERO
            };
        }
    }

    let mut carry = [F128::ZERO; STATE_SIZE];
    for slot in 0..w {
        let local = slot & (stride - 1);
        let path_idx = slot >> family.stride_log();
        let in_family = path_idx < family.n_paths && local < family.depth;

        let raw: [F128; STATE_SIZE] = if in_family {
            let carried = if local == 0 {
                paths[path_idx].entry
            } else {
                [cr[0][slot], cr[1][slot]]
            };
            cr[0][slot] = carried[0];
            cr[1][slot] = carried[1];
            let dv = d[slot];
            let mix = |i: usize| carried[i] + dv * (carried[i] + sib[i][slot]);
            let a = [mix(0), mix(1)];
            let b0 = a[0] + carried[0] + sib[0][slot];
            let b1 = a[1] + carried[1] + sib[1][slot];
            [a[0], a[1], b0 + iv_flat[0], b1 + iv_flat[1]]
        } else {
            carry
        };

        let (st0, stout) = run_perm(raw);
        for j in 0..STATE_SIZE {
            s0[j][slot] = st0[j];
            s_out[j][slot] = stout[j];
            c[j][slot] = stout[j];
        }
        carry = stout;

        if in_family {
            let digest = [stout[0] + raw[0], stout[1] + raw[1]];
            if local == family.depth - 1 {
                roots.push(digest);
                if family.root_copy_offset().is_some() {
                    // The next slot is the spare tail selected by NODENS, so
                    // the existing CR-chain relation proves this copy.
                    cr[0][slot + 1] = digest[0];
                    cr[1][slot + 1] = digest[1];
                }
            } else {
                // The next node's carried-in digest.
                cr[0][slot + 1] = digest[0];
                cr[1][slot + 1] = digest[1];
            }
        }
    }

    FfMerklePathColumns {
        cr,
        sib,
        d,
        c,
        s0,
        s_out,
        roots,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenger::{Challenger, FsLaneChallenger};
    use crate::deep_chain::relations::{
        RelationColumns, claimed_refs, prove_column_relation, prove_shift_discharge,
        verify_column_relation, verify_shift_discharge,
    };
    use crate::deep_chain::schedule::carry_selection_terms;
    use crate::deep_chain::source_tree::mds_weights_pub;
    use crate::deep_chain::{LaneClaimGroup, prove_deep_chain_walk, verify_deep_chain_walk};
    use crate::lincheck::build_eq_table;
    use noid_poseidon2b::native::compress_flat_feed_forward_with_tag;
    use noid_poseidon2b::native::domain::{TAG_CAPSNODE, capacity_iv_flat};

    fn flat_lane(x: u128) -> F128 {
        F128::new(x as u64, (x >> 64) as u64)
    }

    fn lanes_of(h: &[u8; 32]) -> [F128; 2] {
        [
            flat_lane(u128::from_le_bytes(h[..16].try_into().unwrap())),
            flat_lane(u128::from_le_bytes(h[16..].try_into().unwrap())),
        ]
    }

    /// The family replay must reproduce the NATIVE 1-perm feed-forward
    /// compress chain digest per node convention (`is_left = bit k == 0`,
    /// direction bit true = the carried digest is the right child).
    #[test]
    fn chain_matches_native_compress() {
        let iv = capacity_iv_flat(TAG_CAPSNODE);
        let iv_flat = [flat_lane(iv[0]), flat_lane(iv[1])];
        let depth = 5usize;
        let entry_bytes: [u8; 32] = {
            let mut b = [0u8; 32];
            b[0] = 7;
            b[17] = 9;
            b
        };
        let sib_bytes: Vec<[u8; 32]> = (0..depth)
            .map(|k| {
                let mut b = [0u8; 32];
                b[1] = k as u8 + 1;
                b[20] = 0xA0 ^ k as u8;
                b
            })
            .collect();
        let leaf_index = 0b10110usize;

        // Native chain.
        let mut h = entry_bytes;
        for (k, s) in sib_bytes.iter().enumerate() {
            let is_left = (leaf_index >> k) & 1 == 0;
            h = if is_left {
                compress_flat_feed_forward_with_tag(TAG_CAPSNODE, &h, s)
            } else {
                compress_flat_feed_forward_with_tag(TAG_CAPSNODE, s, &h)
            };
        }
        let expect = lanes_of(&h);

        // Family replay (w_log 3: stride 8 holds the depth-5 chain).
        let family = FfMerklePathFamily { depth, n_paths: 1 };
        let witness = FfMerklePathWitness {
            entry: lanes_of(&entry_bytes),
            siblings: sib_bytes.iter().map(lanes_of).collect(),
            directions: (0..depth).map(|k| (leaf_index >> k) & 1 == 1).collect(),
        };
        let cols = build_ff_merkle_path_columns(&family, iv_flat, &[witness], 3);
        assert_eq!(
            cols.roots[0], expect,
            "ff chain root != native compress chain"
        );
        let root_copy = family.root_copy_offset().expect("depth-5 tail");
        assert_eq!(
            [cols.cr[0][root_copy], cols.cr[1][root_copy]],
            expect,
            "root-copy CR cell"
        );
        let fixed = ff_merkle_fixed_patterns(&family, iv_flat);
        assert_eq!(
            fixed[0].table[root_copy],
            F128::ZERO,
            "root copy is not NODE"
        );
        assert_eq!(fixed[1].table[root_copy], F128::ONE, "root copy is NODENS");
    }

    fn mle(col: &[F128], point: &[F128]) -> F128 {
        let eq = build_eq_table(point);
        let mut acc = F128::ZERO;
        for (v, e) in col.iter().zip(eq.iter()) {
            acc += *v * *e;
        }
        acc
    }

    /// Test-side replay mirroring [`build_ff_merkle_path_columns`] but with
    /// FIELD direction values and optional carried-in overrides — the
    /// adversarial witnesses the precise negatives need: a non-boolean
    /// direction (every relation but booleanity holds algebraically) and a
    /// broken carried-digest chain (every relation but the CR-chain holds).
    fn replay(
        family: &FfMerklePathFamily,
        iv_flat: [F128; 2],
        entries: &[[F128; 2]],
        sibs: &[Vec<[F128; 2]>],
        dirs: &[Vec<F128>],
        cr_breaks: &[(usize, [F128; 2])],
        w_log: usize,
    ) -> FfMerklePathColumns {
        let w = 1usize << w_log;
        let stride = family.stride();
        let mut cr: [Vec<F128>; 2] = std::array::from_fn(|_| vec![F128::ZERO; w]);
        let mut sib: [Vec<F128>; 2] = std::array::from_fn(|_| vec![F128::ZERO; w]);
        let mut d = vec![F128::ZERO; w];
        let mut c: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; w]);
        let mut s0: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; w]);
        let mut s_out: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; w]);
        let mut roots = Vec::new();
        for p in 0..family.n_paths {
            let base = p * stride;
            for k in 0..family.depth {
                sib[0][base + k] = sibs[p][k][0];
                sib[1][base + k] = sibs[p][k][1];
                d[base + k] = dirs[p][k];
            }
        }
        let mut carry = [F128::ZERO; STATE_SIZE];
        for slot in 0..w {
            let local = slot & (stride - 1);
            let path_idx = slot >> family.stride_log();
            let in_family = path_idx < family.n_paths && local < family.depth;
            let raw: [F128; STATE_SIZE] = if in_family {
                let mut carried = if local == 0 {
                    entries[path_idx]
                } else {
                    [cr[0][slot], cr[1][slot]]
                };
                if let Some((_, forced)) = cr_breaks.iter().find(|(s, _)| *s == slot) {
                    carried = *forced;
                }
                cr[0][slot] = carried[0];
                cr[1][slot] = carried[1];
                let dv = d[slot];
                let mix = |i: usize| carried[i] + dv * (carried[i] + sib[i][slot]);
                let a = [mix(0), mix(1)];
                let b0 = a[0] + carried[0] + sib[0][slot];
                let b1 = a[1] + carried[1] + sib[1][slot];
                [a[0], a[1], b0 + iv_flat[0], b1 + iv_flat[1]]
            } else {
                carry
            };
            let (st0, stout) = run_perm(raw);
            for j in 0..STATE_SIZE {
                s0[j][slot] = st0[j];
                s_out[j][slot] = stout[j];
                c[j][slot] = stout[j];
            }
            carry = stout;
            if in_family {
                let digest = [stout[0] + raw[0], stout[1] + raw[1]];
                if local == family.depth - 1 {
                    roots.push(digest);
                    if family.root_copy_offset().is_some() {
                        cr[0][slot + 1] = digest[0];
                        cr[1][slot + 1] = digest[1];
                    }
                } else {
                    cr[0][slot + 1] = digest[0];
                    cr[1][slot + 1] = digest[1];
                }
            }
        }
        FfMerklePathColumns {
            cr,
            sib,
            d,
            c,
            s0,
            s_out,
            roots,
        }
    }

    /// Run the family's full region DAG over the given column data: carry
    /// selection → walk → substitution (ghost-carry base + NODE wiring),
    /// then the CR-chain and booleanity zero-checks, discharge every claim
    /// by direct MLE, and check the entry/root cell pins. `check_chain` /
    /// `check_bool` gate the two zero-checks so the precise negatives can
    /// show each is the UNIQUE rejecting relation for its witness class.
    #[allow(clippy::too_many_arguments)]
    fn run_dag(
        family: &FfMerklePathFamily,
        iv_flat: [F128; 2],
        cols: &FfMerklePathColumns,
        committed: &[&[F128]],
        entries: &[[F128; 2]],
        w_log: usize,
        check_chain: bool,
        check_bool: bool,
    ) -> Result<(), String> {
        let refs = FfMerkleFamilyRefs {
            cr: [0, 1],
            sib: [2, 3],
            d: 4,
            c: [5, 6, 7, 8],
            node: 0,
            nodens: 1,
            start: 2,
            iv: [3, 4],
        };
        let fixed = ff_merkle_fixed_patterns(family, iv_flat);
        let internal: Vec<&[F128]> = cols.s_out.iter().map(|c| c.as_slice()).collect();
        let mut ch_p = FsLaneChallenger::new(b"ff-merkle-dag");
        let mut ch_v = FsLaneChallenger::new(b"ff-merkle-dag");
        let mut pending: Vec<(usize, Vec<F128>, F128)> = Vec::new();

        // A claim-discharge helper shared by every relation below.
        let discharge = |terms: &[RelationTerm],
                         final_values: &[F128],
                         point: &[F128],
                         pending: &mut Vec<(usize, Vec<F128>, F128)>,
                         ch_p: &mut FsLaneChallenger,
                         ch_v: &mut FsLaneChallenger|
         -> Result<[F128; STATE_SIZE], String> {
            let mut internal_values = [F128::ZERO; STATE_SIZE];
            for (r, v) in claimed_refs(terms).iter().zip(final_values.iter()) {
                match r {
                    ColRef::Committed(cc) => pending.push((*cc, point.to_vec(), *v)),
                    ColRef::CommittedShift(cc) => {
                        let (pr, _) = prove_shift_discharge(committed[*cc], point, *v, ch_p);
                        let pt = verify_shift_discharge(w_log, point, *v, &pr, ch_v)
                            .map_err(|e| format!("shift: {e}"))?;
                        pending.push((*cc, pt, pr.final_value));
                    }
                    ColRef::Internal(j) => internal_values[*j] = *v,
                    _ => unreachable!("unexpected claimed ref"),
                }
            }
            Ok(internal_values)
        };

        // Carry selection → walk group.
        let beta = ch_p.sample_f128();
        assert_eq!(beta, ch_v.sample_f128());
        let sel_terms = carry_selection_terms(&refs.c, beta);
        let rho: Vec<F128> = ch_p.sample_f128_vec(w_log);
        let _ = ch_v.sample_f128_vec(w_log);
        let (sp, _, _) = prove_column_relation(
            F128::ZERO,
            &rho,
            &sel_terms,
            &RelationColumns {
                committed,
                internal: &internal,
                fixed: &fixed,
            },
            &mut ch_p,
        );
        let sel_point =
            verify_column_relation(w_log, F128::ZERO, &rho, &sel_terms, &fixed, &sp, &mut ch_v)
                .map_err(|e| format!("selection: {e}"))?;
        let group_values = discharge(
            &sel_terms,
            &sp.final_values,
            &sel_point,
            &mut pending,
            &mut ch_p,
            &mut ch_v,
        )?;

        // Walk.
        let groups = vec![LaneClaimGroup {
            point: sel_point,
            values: group_values,
        }];
        let (wp, _) = prove_deep_chain_walk(&cols.s0, &groups, &mut ch_p);
        let terminal = verify_deep_chain_walk(w_log, &groups, &wp, &mut ch_v)
            .map_err(|e| format!("walk: {e}"))?;

        // Substitution: the shared ghost-carry base + the NODE wiring.
        let alpha = ch_p.sample_f128();
        assert_eq!(alpha, ch_v.sample_f128());
        let m = mds_weights_pub(alpha);
        let mut sub_terms: Vec<RelationTerm> = (0..STATE_SIZE)
            .map(|j| RelationTerm {
                coeff: m[j],
                factors: vec![ColRef::CommittedShift(refs.c[j])],
            })
            .collect();
        sub_terms.extend(ff_merkle_substitution_terms(&refs, alpha));
        let mut target = F128::ZERO;
        let mut p = F128::ONE;
        for e in 0..STATE_SIZE {
            p = p * alpha;
            target += p * terminal.values[e];
        }
        let (subp, _, _) = prove_column_relation(
            target,
            &terminal.point,
            &sub_terms,
            &RelationColumns {
                committed,
                internal: &[],
                fixed: &fixed,
            },
            &mut ch_p,
        );
        let sub_point = verify_column_relation(
            w_log,
            target,
            &terminal.point,
            &sub_terms,
            &fixed,
            &subp,
            &mut ch_v,
        )
        .map_err(|e| format!("substitution: {e}"))?;
        discharge(
            &sub_terms,
            &subp.final_values,
            &sub_point,
            &mut pending,
            &mut ch_p,
            &mut ch_v,
        )?;

        // CR-chain zero-check.
        if check_chain {
            let gamma = ch_p.sample_f128();
            assert_eq!(gamma, ch_v.sample_f128());
            let chain_terms = ff_merkle_chain_terms(&refs, gamma);
            let rho2: Vec<F128> = ch_p.sample_f128_vec(w_log);
            let _ = ch_v.sample_f128_vec(w_log);
            let (cp, _, _) = prove_column_relation(
                F128::ZERO,
                &rho2,
                &chain_terms,
                &RelationColumns {
                    committed,
                    internal: &[],
                    fixed: &fixed,
                },
                &mut ch_p,
            );
            let chain_point = verify_column_relation(
                w_log,
                F128::ZERO,
                &rho2,
                &chain_terms,
                &fixed,
                &cp,
                &mut ch_v,
            )
            .map_err(|e| format!("chain: {e}"))?;
            discharge(
                &chain_terms,
                &cp.final_values,
                &chain_point,
                &mut pending,
                &mut ch_p,
                &mut ch_v,
            )?;
        }

        // Direction booleanity zero-check.
        if check_bool {
            let bool_terms = ff_merkle_booleanity_terms(&refs);
            let rho3: Vec<F128> = ch_p.sample_f128_vec(w_log);
            let _ = ch_v.sample_f128_vec(w_log);
            let (bp, _, _) = prove_column_relation(
                F128::ZERO,
                &rho3,
                &bool_terms,
                &RelationColumns {
                    committed,
                    internal: &[],
                    fixed: &fixed,
                },
                &mut ch_p,
            );
            let bool_point = verify_column_relation(
                w_log,
                F128::ZERO,
                &rho3,
                &bool_terms,
                &fixed,
                &bp,
                &mut ch_v,
            )
            .map_err(|e| format!("booleanity: {e}"))?;
            discharge(
                &bool_terms,
                &bp.final_values,
                &bool_point,
                &mut pending,
                &mut ch_p,
                &mut ch_v,
            )?;
        }

        assert_eq!(ch_p.sample_f128(), ch_v.sample_f128(), "lockstep");
        for (cc, pt, v) in &pending {
            if mle(committed[*cc], pt) != *v {
                return Err(format!("claim on column {cc} is false"));
            }
        }

        // Entry pins and root LinExpr pins (cell reads — pin_eq rows in the
        // assembly). The roots pin against the replay's own recomputation.
        let stride = family.stride();
        for (pi, entry) in entries.iter().enumerate() {
            let base = pi * stride;
            for i in 0..2 {
                if committed[refs.cr[i]][base] != entry[i] {
                    return Err(format!("entry pin mismatch on path {pi}"));
                }
            }
            for i in 0..2 {
                let root = if let Some(root_copy) = family.root_copy_offset() {
                    committed[refs.cr[i]][base + root_copy]
                } else {
                    let last = base + family.depth - 1;
                    let crv = committed[refs.cr[i]][last];
                    let sibv = committed[refs.sib[i]][last];
                    let dv = committed[refs.d][last];
                    committed[refs.c[i]][last] + crv + dv * (crv + sibv)
                };
                if root != cols.roots[pi][i] {
                    return Err(format!("root pin mismatch on path {pi}"));
                }
            }
        }
        Ok(())
    }

    /// The family's full region DAG: honest roundtrip plus the precise
    /// negatives — each zero-check is shown to be the UNIQUE relation
    /// rejecting its adversarial witness class (a deleted-relation mutant
    /// cannot survive), and a plainly corrupted committed cell dies in the
    /// substitution.
    #[test]
    fn ff_merkle_region_dag_roundtrip_and_negatives() {
        let iv = capacity_iv_flat(TAG_CAPSNODE);
        let iv_flat = [flat_lane(iv[0]), flat_lane(iv[1])];
        let depth = 5usize;
        let family = FfMerklePathFamily { depth, n_paths: 2 };
        let w_log = 4usize; // 2 paths × stride 8

        let mut seed = 0xFF31u64;
        let mut next = || {
            seed = seed.wrapping_add(0x9E3779B97F4A7C15);
            let mut z = seed;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
            z ^= z >> 31;
            F128 {
                lo: z,
                hi: z.rotate_left(11),
            }
        };
        let entries: Vec<[F128; 2]> = (0..2).map(|_| [next(), next()]).collect();
        let sibs: Vec<Vec<[F128; 2]>> = (0..2)
            .map(|_| (0..depth).map(|_| [next(), next()]).collect())
            .collect();
        let dir_bits: Vec<Vec<bool>> = vec![
            (0..depth).map(|k| (0b10110 >> k) & 1 == 1).collect(),
            (0..depth).map(|k| (0b01011 >> k) & 1 == 1).collect(),
        ];
        let dirs: Vec<Vec<F128>> = dir_bits
            .iter()
            .map(|bits| {
                bits.iter()
                    .map(|&b| if b { F128::ONE } else { F128::ZERO })
                    .collect()
            })
            .collect();

        // The honest replay must agree with the production builder.
        let cols = replay(&family, iv_flat, &entries, &sibs, &dirs, &[], w_log);
        let witnesses: Vec<FfMerklePathWitness> = (0..2)
            .map(|p| FfMerklePathWitness {
                entry: entries[p],
                siblings: sibs[p].clone(),
                directions: dir_bits[p].clone(),
            })
            .collect();
        let built = build_ff_merkle_path_columns(&family, iv_flat, &witnesses, w_log);
        assert_eq!(built.roots, cols.roots, "replay oracle vs builder roots");
        for j in 0..STATE_SIZE {
            assert_eq!(built.c[j], cols.c[j], "replay oracle vs builder c[{j}]");
        }

        let table = |c: &FfMerklePathColumns| -> Vec<Vec<F128>> {
            vec![
                c.cr[0].clone(),
                c.cr[1].clone(),
                c.sib[0].clone(),
                c.sib[1].clone(),
                c.d.clone(),
                c.c[0].clone(),
                c.c[1].clone(),
                c.c[2].clone(),
                c.c[3].clone(),
            ]
        };
        let run =
            |cols: &FfMerklePathColumns, committed: &[Vec<F128>], chain: bool, boolean: bool| {
                let refs: Vec<&[F128]> = committed.iter().map(|c| c.as_slice()).collect();
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run_dag(
                        &family, iv_flat, cols, &refs, &entries, w_log, chain, boolean,
                    )
                }))
                .unwrap_or_else(|_| Err("native relation prover rejected witness".into()))
            };

        let honest = table(&cols);
        run(&cols, &honest, true, true).expect("honest ff-merkle DAG verifies");

        // Corrupted committed sibling cell: dies in the substitution claims.
        {
            let mut bad = honest.clone();
            bad[2][3] += F128::ONE;
            assert!(
                run(&cols, &bad, true, true).is_err(),
                "corrupted sibling accepted"
            );
        }

        // The exposed root is not a free tail cell: NODENS extends the
        // existing CR chain into it, and the direct root pin consumes it.
        {
            let mut bad = honest.clone();
            let root_copy = family.root_copy_offset().expect("depth-5 tail");
            bad[0][root_copy] += F128::ONE;
            assert!(
                run(&cols, &bad, true, true).is_err(),
                "corrupted root-copy cell accepted"
            );
        }

        // Broken carried-digest chain, everything downstream replayed
        // consistently: ONLY the CR-chain relation rejects it.
        {
            let breaks = [(2usize, [next(), next()])];
            let forged = replay(&family, iv_flat, &entries, &sibs, &dirs, &breaks, w_log);
            let t = table(&forged);
            assert!(
                run(&forged, &t, true, true).is_err(),
                "broken CR chain accepted"
            );
            run(&forged, &t, false, true).expect("chain break must be invisible elsewhere");
        }

        // Non-boolean direction, replayed consistently: ONLY booleanity
        // rejects it.
        {
            let mut dirs2 = dirs.clone();
            dirs2[1][2] = next();
            let forged = replay(&family, iv_flat, &entries, &sibs, &dirs2, &[], w_log);
            let t = table(&forged);
            assert!(
                run(&forged, &t, true, true).is_err(),
                "non-boolean direction accepted"
            );
            run(&forged, &t, true, false).expect("non-boolean dir must be invisible elsewhere");
        }
    }

    /// A power-of-two path has no spare stride slot for the historical
    /// root-copy cell.  Its public root is therefore pinned to the final
    /// node's already-constrained feed-forward expression
    ///
    /// `C_i + CR_i + D * (CR_i + SIB_i)`.
    ///
    /// This is the exact depth/stride shape selected for both capsule
    /// authentication paths.  Exercise the full DAG and every committed
    /// input to that expression so a missing composite-root wire cannot be
    /// hidden by the otherwise-honest Merkle walk.
    #[test]
    fn depth8_composite_root_roundtrip_and_final_cell_negatives() {
        let iv = capacity_iv_flat(TAG_CAPSNODE);
        let iv_flat = [flat_lane(iv[0]), flat_lane(iv[1])];
        let family = FfMerklePathFamily {
            depth: 8,
            n_paths: 1,
        };
        let w_log = 3usize;
        assert_eq!(family.stride(), 8);
        assert_eq!(family.root_copy_offset(), None);

        let entry = [
            F128::new(0x1020_3040_5060_7080, 0x90a0_b0c0_d0e0_f001),
            F128::new(0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210),
        ];
        let siblings: Vec<[F128; 2]> = (0..family.depth)
            .map(|k| {
                [
                    F128::new(0x100 + k as u64, 0x200 + (3 * k) as u64),
                    F128::new(0x300 + (5 * k) as u64, 0x400 + (7 * k) as u64),
                ]
            })
            .collect();
        let directions: Vec<bool> = (0..family.depth)
            .map(|k| (0b1010_0110usize >> k) & 1 == 1)
            .collect();
        let witness = FfMerklePathWitness {
            entry,
            siblings,
            directions,
        };
        let cols = build_ff_merkle_path_columns(&family, iv_flat, &[witness], w_log);
        let last = family.depth - 1;
        for lane in 0..2 {
            let cr = cols.cr[lane][last];
            let sib = cols.sib[lane][last];
            let d = cols.d[last];
            let composite = cols.c[lane][last] + cr + d * (cr + sib);
            assert_eq!(composite, cols.roots[0][lane], "lane {lane} root");
        }

        let table = |c: &FfMerklePathColumns| -> Vec<Vec<F128>> {
            vec![
                c.cr[0].clone(),
                c.cr[1].clone(),
                c.sib[0].clone(),
                c.sib[1].clone(),
                c.d.clone(),
                c.c[0].clone(),
                c.c[1].clone(),
                c.c[2].clone(),
                c.c[3].clone(),
            ]
        };
        let run = |committed: &[Vec<F128>]| {
            let refs: Vec<&[F128]> = committed.iter().map(Vec::as_slice).collect();
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                run_dag(&family, iv_flat, &cols, &refs, &[entry], w_log, true, true)
            }))
            .unwrap_or_else(|_| Err("native relation prover rejected witness".into()))
        };

        let honest = table(&cols);
        run(&honest).expect("honest depth-8 composite-root DAG verifies");

        for (name, column) in [("CR", 0usize), ("SIB", 2), ("D", 4), ("C", 5)] {
            let mut bad = honest.clone();
            bad[column][last] += F128::ONE;
            assert!(
                run(&bad).is_err(),
                "final {name} mutation survived the composite-root DAG"
            );
        }
    }
}

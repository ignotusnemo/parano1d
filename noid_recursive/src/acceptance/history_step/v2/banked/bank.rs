// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use super::*;
use crate::acceptance::history_step_bank::retirement::{
    CheckedHistoryStepRetirementMatrices, HistoryStepRetirementRequest,
};
use noid_core::Block128;
use noid_ivc_core::field_circuit::f128_to_u128;
use noid_poseidon2b::native::poseidon2b_hash_byte_slices;

#[derive(Clone, Debug)]
pub struct Bank {
    config: Config,
    matrices: [[u8; 32]; 2],
    posts: [[u8; 32]; 2],
    digest: [u8; 32],
    parent_digest: [u8; 32],
    block_digests: [[u8; 32]; 2],
}
impl Bank {
    pub fn pin(matrices: [[u8; 32]; 2], parts: &RuntimeParts) -> Self {
        let config = parts.config;
        let identity = config.identity_bytes();
        let parent_digest = parts.parent_vk.transcript_digest();
        let block_digests = Class::ALL.map(|c| parts.block_vk(c).transcript_digest());
        let spec: Vec<u8> = config
            .io_spec()
            .transcript_lanes()
            .iter()
            .flat_map(|lane| [lane.lo.to_le_bytes(), lane.hi.to_le_bytes()].concat())
            .collect();
        let entries: Vec<u8> = Class::ALL
            .into_iter()
            .flat_map(|c| {
                let entry = config.class(c);
                let shape = entry.shape();
                let mut bytes: Vec<u8> = [
                    shape.m,
                    shape.k_log,
                    shape.k_skip,
                    shape.const_pin.unwrap() + 1,
                ]
                .into_iter()
                .flat_map(|x| (x as u64).to_le_bytes())
                .collect();
                bytes.extend_from_slice(&pcs_params_statement_bytes(&entry.pcs_params()));
                bytes.extend_from_slice(&matrices[c.index()]);
                bytes.extend_from_slice(&block_digests[c.index()]);
                bytes
            })
            .collect();
        let posts = Class::ALL.map(|c| {
            poseidon2b_hash_byte_slices(
                b"NOID/HISTORY-STEP/BANKED-POST-COMMIT/V2",
                &[&[c.wire_id()], &identity, &spec, &entries, &parent_digest],
            )
        });
        let digest = poseidon2b_hash_byte_slices(
            b"NOID/HISTORY-STEP/BANKED-BANK/V2",
            &[
                &identity,
                &spec,
                &entries,
                &parent_digest,
                &posts[0],
                &posts[1],
            ],
        );
        Self {
            config,
            matrices,
            posts,
            digest,
            parent_digest,
            block_digests,
        }
    }
    pub fn config(&self) -> Config {
        self.config
    }
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub fn matrix_digest(&self, class: Class) -> [u8; 32] {
        self.matrices[class.index()]
    }
    pub fn post_commit_digest(&self, class: Class) -> [u8; 32] {
        self.posts[class.index()]
    }
    pub(super) fn check_parts(&self, parts: &RuntimeParts) -> Result<(), V2Error> {
        if self.config != parts.config
            || self.parent_digest != parts.parent_vk.transcript_digest()
            || self.block_digests != Class::ALL.map(|c| parts.block_vk(c).transcript_digest())
        {
            return Err(V2Error::Runtime);
        }
        Ok(())
    }
    pub(super) fn authenticate(
        &self,
        class: Class,
        matrix: &HistoryStepMatrixLease,
    ) -> Result<(), V2Error> {
        if matrix.field_shape() != self.config.class(class).shape()
            || matrix.statement_digest() != self.matrix_digest(class)
        {
            return Err(V2Error::Matrix);
        }
        Ok(())
    }
    pub(super) fn initial_io(
        &self,
        origin: &Origin,
        class: Class,
        end: &ChainAccumulator,
    ) -> Vec<F128> {
        let mut io = vec![F128::ZERO; IO_LEN];
        io[BASE] = F128::ONE;
        io[TIP_CLASS] = f128_from_u128(class.wire_id() as u128);
        for (offset, digest) in [(BANK, self.digest), (ORIGIN, origin.request_binding)] {
            io[offset..offset + 2].copy_from_slice(&flat_digest_lanes(&digest));
        }
        for class in Class::ALL {
            for (offset, digest) in [
                (MATRIX, self.matrix_digest(class)),
                (POST, self.post_commit_digest(class)),
            ] {
                let start = offset + 2 * class.index();
                io[start..start + 2].copy_from_slice(&flat_digest_lanes(&digest));
            }
        }
        io[ORIGIN_ID..ORIGIN_ID + 2].copy_from_slice(&digest_lanes(&origin.parent_id).map(flat_of));
        io[ORIGIN_ACC..ORIGIN_ACC + 10].copy_from_slice(&block_acc_lanes(&origin.boundary));
        io[ACC..ACC + 10].copy_from_slice(&block_acc_lanes(end));
        io
    }
    pub(super) fn parse(&self, io: &[F128]) -> Result<ParsedIo, V2Error> {
        if io.len() != IO_LEN || io[BANK..BANK + 2] != flat_digest_lanes(&self.digest) {
            return Err(V2Error::Io);
        }
        for class in Class::ALL {
            for (offset, digest) in [
                (MATRIX, self.matrix_digest(class)),
                (POST, self.post_commit_digest(class)),
            ] {
                let start = offset + 2 * class.index();
                if io[start..start + 2] != flat_digest_lanes(&digest) {
                    return Err(V2Error::Io);
                }
            }
        }
        let class = match io[TIP_CLASS] {
            F128::ZERO => Class::Small,
            F128::ONE => Class::Large,
            _ => return Err(V2Error::Io),
        };
        let base = match io[BASE] {
            F128::ZERO => false,
            F128::ONE => true,
            _ => return Err(V2Error::Io),
        };
        let mut claims = [None, None];
        for class in Class::ALL {
            let lane = Lane::for_class(class);
            claims[class.index()] = match io[lane.live] {
                F128::ZERO if io[lane.point..lane.live].iter().all(|x| *x == F128::ZERO) => None,
                F128::ONE => Some(C1MatrixAccClaim {
                    point: io[lane.point..lane.value]
                        .chunks_exact(2)
                        .map(|x| F256::new(x[0], x[1]))
                        .collect(),
                    value: F256::new(io[lane.value], io[lane.value + 1]),
                }),
                _ => return Err(V2Error::Io),
            };
        }
        if base == claims.iter().any(Option::is_some) {
            return Err(V2Error::Io);
        }
        let origin = Origin {
            request_binding: digest_from_flat(&io[ORIGIN..ORIGIN + 2]),
            parent_id: digest_from_state_lanes(&io[ORIGIN_ID..ORIGIN_ID + 2]),
            boundary: accumulator_from_flat(&io[ORIGIN_ACC..ORIGIN_ACC + 10])?,
            next_bank: self.digest,
        };
        origin.check(self)?;
        let accumulator = accumulator_from_flat(&io[ACC..ACC + 10])?;
        if accumulator.height < self.config.activation_height()
            || base != (accumulator.height == self.config.activation_height())
        {
            return Err(V2Error::Boundary);
        }
        Ok(ParsedIo {
            class,
            claims,
            origin,
            accumulator,
        })
    }
}

pub(super) struct ParsedIo {
    pub class: Class,
    pub claims: [Option<C1MatrixAccClaim>; 2],
    pub origin: Origin,
    pub accumulator: ChainAccumulator,
}

fn accumulator_from_flat(lanes: &[F128]) -> Result<ChainAccumulator, V2Error> {
    let lanes: [Block128; 10] = lanes
        .iter()
        .map(|lane| Block128(noid_core::hardware::flat_to_tower_u128(f128_to_u128(*lane))))
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| V2Error::Io)?;
    ChainAccumulator::from_lanes(lanes).map_err(|_| V2Error::Io)
}
fn digest_from_flat(lanes: &[F128]) -> [u8; 32] {
    let mut digest = [0; 32];
    for (chunk, lane) in digest.chunks_exact_mut(16).zip(lanes) {
        chunk.copy_from_slice(&f128_to_u128(*lane).to_le_bytes());
    }
    digest
}
fn digest_from_state_lanes(lanes: &[F128]) -> [u8; 32] {
    let mut digest = [0; 32];
    for (chunk, lane) in digest.chunks_exact_mut(16).zip(lanes) {
        chunk.copy_from_slice(
            &noid_core::hardware::flat_to_tower_u128(f128_to_u128(*lane)).to_le_bytes(),
        );
    }
    digest
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Origin {
    pub(super) request_binding: [u8; 32],
    pub(super) parent_id: [u8; 32],
    pub(super) boundary: ChainAccumulator,
    next_bank: [u8; 32],
}
impl Origin {
    fn from_boundary(
        legacy_bank: [u8; 32],
        next: &Bank,
        parent: &BlockHeader,
        epoch: &BlockHeader,
        boundary: &ChainAccumulator,
    ) -> Result<Self, V2Error> {
        if parent.height.checked_add(1) != Some(next.config.activation_height()) {
            return Err(V2Error::Boundary);
        }
        boundary
            .validate_local_header_boundary(parent, epoch)
            .map_err(|_| V2Error::Boundary)?;
        let mut boundary_bytes = Vec::new();
        parent.encode(&mut boundary_bytes);
        epoch.encode(&mut boundary_bytes);
        for lane in boundary.to_lanes() {
            boundary_bytes.extend_from_slice(&lane.0.to_le_bytes());
        }
        let request_binding = poseidon2b_hash_byte_slices(
            b"NOID/HISTORY-STEP/BANKED-VERIFIED-ORIGIN/V2",
            &[
                &legacy_bank,
                &next.digest,
                &next.config.identity_bytes(),
                &boundary_bytes,
            ],
        );
        let origin = Self {
            request_binding,
            parent_id: noid_chain::hash_block_header(parent),
            boundary: boundary.clone(),
            next_bank: next.digest,
        };
        origin.check(next)?;
        Ok(origin)
    }

    /// Supply a hypothetical boundary witness when freezing a scheduled bank
    /// before its real predecessor exists. This returns only an untrusted
    /// statement, never `VerifiedOrigin` or terminal acceptance authority.
    /// The resulting matrix must be rechecked under its final pins and used
    /// with an independently verified real origin on the live chain.
    pub fn for_matrix_freezing(
        legacy_bank: [u8; 32],
        next: &Bank,
        parent: &BlockHeader,
        epoch: &BlockHeader,
        boundary: &ChainAccumulator,
    ) -> Result<Self, V2Error> {
        Self::from_boundary(legacy_bank, next, parent, epoch, boundary)
    }

    pub fn boundary(&self) -> &ChainAccumulator {
        &self.boundary
    }
    pub const fn parent_id(&self) -> [u8; 32] {
        self.parent_id
    }
    pub const fn request_binding(&self) -> [u8; 32] {
        self.request_binding
    }
    pub const fn next_bank(&self) -> [u8; 32] {
        self.next_bank
    }
    pub fn activation_height(&self) -> Result<u64, V2Error> {
        self.boundary
            .height
            .checked_add(1)
            .filter(|h| *h > 1)
            .ok_or(V2Error::Boundary)
    }
    pub(super) fn check(&self, bank: &Bank) -> Result<(), V2Error> {
        if self.next_bank != bank.digest
            || self.activation_height()? != bank.config.activation_height()
        {
            return Err(V2Error::Boundary);
        }
        Ok(())
    }
}

/// Minted only after verifying the legacy proof and every live legacy matrix
/// obligation. A raw peer-supplied origin can never construct this capability.
pub struct VerifiedOrigin(pub(super) Origin);
impl VerifiedOrigin {
    pub fn origin(&self) -> &Origin {
        &self.0
    }
    pub fn from_legacy(
        legacy: &HistoryStepRuntime,
        terminal: &HistoryStepTerminal,
        parent_header: &BlockHeader,
        epoch_header: &BlockHeader,
        next: &Bank,
    ) -> Result<Self, V2Error> {
        noid_chain::consensus::pow::validate_pow(parent_header).map_err(|_| V2Error::Origin)?;
        if next
            .config
            .class(Class::Small)
            .authorization_activation()
            .is_some()
            || parent_header.height.checked_add(1) != Some(next.config.activation_height())
        {
            return Err(V2Error::Boundary);
        }
        let accepted = verify_history_step_terminal(legacy, terminal, parent_header, epoch_header)?;
        let origin = Origin::from_boundary(
            legacy.bank().digest(),
            next,
            parent_header,
            epoch_header,
            accepted.accumulator(),
        )?;
        Ok(Self(origin))
    }

    pub fn from_authorization_boundary(
        previous: &Runtime,
        previous_origin: &VerifiedOrigin,
        terminal: &Terminal,
        parent_header: &BlockHeader,
        epoch_header: &BlockHeader,
        next: &Bank,
    ) -> Result<Self, V2Error> {
        let old_config = previous.bank().config();
        let new_config = next.config();
        if old_config.class(Class::Small).authorization_version()
            != noid_tx::OwnerAuthorizationVersion::V3
            || new_config.class(Class::Small).authorization_version()
                != noid_tx::OwnerAuthorizationVersion::V4
            || old_config.schedule() != new_config.schedule()
            || parent_header.height.checked_add(1) != Some(new_config.activation_height())
            || parent_header.height < old_config.activation_height()
        {
            return Err(V2Error::Boundary);
        }
        noid_chain::consensus::pow::validate_pow(parent_header).map_err(|_| V2Error::Origin)?;
        let accepted = verify_terminal(
            previous,
            previous_origin,
            terminal,
            parent_header,
            epoch_header,
        )?;
        Ok(Self(Origin::from_boundary(
            previous.bank().digest(),
            next,
            parent_header,
            epoch_header,
            accepted.accumulator(),
        )?))
    }

    /// Retire the old rows only after every legacy obligation is closed under
    /// independent release-pinned preprocessing keys. A checked proof under a
    /// caller-labeled matrix key alone cannot mint this capability.
    pub fn from_retirement(
        request: &HistoryStepRetirementRequest,
        checked: CheckedHistoryStepRetirementMatrices,
        next: &Bank,
        keys: &PinnedRetirementKeys,
    ) -> Result<Self, V2Error> {
        noid_chain::consensus::pow::validate_pow(request.parent_header())
            .map_err(|_| V2Error::Origin)?;
        if next
            .config
            .class(Class::Small)
            .authorization_activation()
            .is_some()
            || checked.request_binding() != request.binding()
            || checked.target() != request.target()
            || checked.boundary() != request.boundary()
            || request.target().next_bank_digest() != next.digest()
            || request.target().schedule() != next.config().schedule()
        {
            return Err(V2Error::Origin);
        }
        keys.check_evaluations(&checked)?;
        let origin = Origin::from_boundary(
            request.target().legacy_bank_digest(),
            next,
            request.parent_header(),
            request.epoch_anchor_header(),
            checked.boundary(),
        )?;
        Ok(Self(origin))
    }
}

pub(super) fn install_claim(
    class: Class,
    io: &mut [F128],
    claim: &C1MatrixAccClaim,
) -> Result<(), V2Error> {
    let lane = Lane::for_class(class);
    if io.len() != IO_LEN || claim.point.len() != lane.point_len() {
        return Err(V2Error::Io);
    }
    for (lanes, point) in io[lane.point..lane.value]
        .chunks_exact_mut(2)
        .zip(&claim.point)
    {
        lanes.copy_from_slice(&[point.lo, point.hi]);
    }
    io[lane.value] = claim.value.lo;
    io[lane.value + 1] = claim.value.hi;
    io[lane.live] = F128::ONE;
    io[BASE] = F128::ZERO;
    Ok(())
}

#[cfg(test)]
pub(super) fn fixture() -> (Bank, Origin, ChainAccumulator) {
    use noid_chain::consensus::forks::{ForkSchedule, V2Activation};
    let schedule = ForkSchedule::new(Some(5), V2Activation::new(10, 30)).unwrap();
    let config = Config::new(
        V2Config::with_limits(23, 63, 504, 63, schedule).unwrap(),
        V2Config::with_limits(24, 255, 1020, 63, schedule).unwrap(),
    )
    .unwrap();
    let bank = Bank {
        config,
        matrices: [[11; 32], [12; 32]],
        posts: [[13; 32], [14; 32]],
        digest: [15; 32],
        parent_digest: [16; 32],
        block_digests: [[17; 32], [18; 32]],
    };
    let mut boundary = genesis_accumulator();
    boundary.height = 9;
    let mut end = boundary.clone();
    end.height = 10;
    let origin = Origin {
        request_binding: [31; 32],
        parent_id: [32; 32],
        boundary,
        next_bank: bank.digest,
    };
    (bank, origin, end)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn freezing_statement_preserves_the_boundary_binding_and_grants_no_capability() {
        let (bank, _, _) = fixture();
        let epoch = noid_chain::consensus::genesis_header();
        let mut parent = epoch;
        parent.height = bank.config.activation_height() - 1;
        parent.timestamp += parent.height * 20;
        let boundary = ChainAccumulator {
            height: parent.height,
            tip_semantic_id: noid_chain::block_header::semantic_header_id(&parent),
            state_root: parent.state_root,
            log_slots: parent.log_slots,
            active_slot_count: parent.active_slot_count,
            alloc_counter: parent.alloc_counter,
            epoch_anchor_id: noid_chain::hash_block_header(&epoch),
        };
        let raw = Origin::for_matrix_freezing([99; 32], &bank, &parent, &epoch, &boundary).unwrap();
        let mut bytes = Vec::new();
        parent.encode(&mut bytes);
        epoch.encode(&mut bytes);
        for lane in boundary.to_lanes() {
            bytes.extend_from_slice(&lane.0.to_le_bytes());
        }
        // Same encoding as the already measured legacy-verification path.
        assert_eq!(
            raw.request_binding(),
            poseidon2b_hash_byte_slices(
                b"NOID/HISTORY-STEP/BANKED-VERIFIED-ORIGIN/V2",
                &[
                    &[99; 32],
                    &bank.digest(),
                    &bank.config.identity_bytes(),
                    &bytes
                ],
            )
        );
        let mut wrong = boundary;
        wrong.state_root[0] ^= 1;
        assert!(Origin::for_matrix_freezing([99; 32], &bank, &parent, &epoch, &wrong).is_err());
        parent.height += 1;
        assert!(Origin::for_matrix_freezing([99; 32], &bank, &parent, &epoch, &wrong).is_err());
        // `raw` is deliberately only an Origin: there is no conversion to
        // VerifiedOrigin without legacy proof verification or pinned retirement.
    }

    #[test]
    fn base_cannot_import_claims_or_change_any_bank_pin() {
        let (bank, origin, end) = fixture();
        for class in Class::ALL {
            let io = bank.initial_io(&origin, class, &end);
            assert_eq!(bank.parse(&io).unwrap().origin, origin);
            for index in BANK..ORIGIN {
                let mut changed = io.clone();
                changed[index] += F128::ONE;
                assert!(bank.parse(&changed).is_err(), "bank pin {index}");
            }
            for index in POINT..ACC {
                let mut changed = io.clone();
                changed[index] = F128::ONE;
                assert!(bank.parse(&changed).is_err(), "imported base claim {index}");
            }
            let mut changed = io;
            changed[TIP_CLASS] = f128_from_u128(2);
            assert!(bank.parse(&changed).is_err());
        }
    }

    #[test]
    fn routing_preserves_the_other_lane_and_cannot_reset_the_origin() {
        let (bank, origin, mut end) = fixture();
        let mut io = bank.initial_io(&origin, Class::Large, &end);
        end.height += 1;
        io[ACC..ACC + 10].copy_from_slice(&block_acc_lanes(&end));
        assert!(bank.parse(&io).is_err());
        for class in [Class::Large, Class::Small, Class::Small] {
            let prior = io.clone();
            let lane = Lane::for_class(class);
            let claim = C1MatrixAccClaim {
                point: vec![F256::ONE; lane.point_len()],
                value: F256::ONE,
            };
            install_claim(class, &mut io, &claim).unwrap();
            let parsed = bank.parse(&io).unwrap();
            assert_eq!(parsed.origin, origin);
            assert_eq!(parsed.claims[class.index()], Some(claim));
            let other = Lane::for_class(if class == Class::Small {
                Class::Large
            } else {
                Class::Small
            });
            assert_eq!(
                &prior[other.point..=other.live],
                &io[other.point..=other.live]
            );
        }
        let mut changed = io.clone();
        changed[BASE] = F128::ONE;
        assert!(bank.parse(&changed).is_err());
        changed = io.clone();
        changed[POINT..ACC].fill(F128::ZERO);
        assert!(bank.parse(&changed).is_err());
        changed = io;
        changed[ORIGIN_ACC] = flat_of(Block128(10));
        assert!(bank.parse(&changed).is_err());
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Matrix-free origin verification. The old terminal is replayed, its exact
//! outstanding claims are reduced, and every live class has a pinned sparse
//! evaluation proof. No peer-supplied boundary or preprocessing root is trusted.

use super::*;
use crate::acceptance::history_step_bank::retirement::{
    CheckedHistoryStepRetirementMatrices, HistoryStepRetirementEvaluation,
    HistoryStepRetirementReduction, HistoryStepRetirementTarget,
};
use crate::acceptance::history_step_bank::{
    CanonicalHistoryStepClassId, PinnedHistoryStepClassBank,
};
use noid_ivc_core::matrix_claim::sparse_c1::{
    SparseMatrixEvaluationKey, SparseMatrixEvaluationProof, MAX_SPARSE_EVALUATION_PROOF_BYTES,
};

const MAGIC: &[u8; 8] = b"O1V2OR02";
const MAX_REDUCTION_BYTES: usize = 8192;
/// Independent transport bound, below the process-wide inbound allowance.
pub const MAX_RETIREMENT_ORIGIN_BYTES: usize =
    noid_chain::consensus::wire_limits::MAX_V2_FORK_ORIGIN_TRANSPORT_BYTES;

/// These keys come from release material, never from a fork certificate. The
/// caller pins the preprocessing digests independently of the encoded keys.
pub struct PinnedRetirementKeys {
    legacy_bank: [u8; 32],
    keys: [SparseMatrixEvaluationKey; 2],
}

impl PinnedRetirementKeys {
    pub fn from_banked_release(
        bank: &Bank,
        encoded: [&[u8]; 2],
        release_pins: [[u8; 32]; 2],
    ) -> Result<Self, V2Error> {
        let mut keys = Vec::with_capacity(2);
        for class in Class::ALL {
            let key = SparseMatrixEvaluationKey::from_bytes_pinned(
                encoded[class.index()],
                release_pins[class.index()],
            )
            .map_err(retirement_error)?;
            if key.shape() != bank.config().class(class).shape()
                || key.matrix_digest() != bank.matrix_digest(class)
            {
                return Err(V2Error::Origin);
            }
            keys.push(key);
        }
        Ok(Self {
            legacy_bank: bank.digest(),
            keys: keys.try_into().map_err(|_| V2Error::Origin)?,
        })
    }

    pub fn key(&self, class: CanonicalHistoryStepClassId) -> &SparseMatrixEvaluationKey {
        &self.keys[class.index()]
    }

    pub fn from_release(
        bank: &PinnedHistoryStepClassBank,
        encoded: [&[u8]; 2],
        release_pins: [[u8; 32]; 2],
    ) -> Result<Self, V2Error> {
        let mut keys = Vec::with_capacity(2);
        for index in 0..2 {
            let key =
                SparseMatrixEvaluationKey::from_bytes_pinned(encoded[index], release_pins[index])
                    .map_err(retirement_error)?;
            let entry = bank.entry(CanonicalHistoryStepClassId::from_index(index).unwrap());
            if key.shape() != entry.shape() || key.matrix_digest() != entry.matrix_digest() {
                return Err(V2Error::Origin);
            }
            keys.push(key);
        }
        Ok(Self {
            legacy_bank: bank.digest(),
            keys: keys.try_into().map_err(|_| V2Error::Origin)?,
        })
    }

    pub const fn legacy_bank_digest(&self) -> [u8; 32] {
        self.legacy_bank
    }

    /// A matrix hash inside a preprocessing key is not authentication of that
    /// key. Only these independently release-pinned key digests can close an
    /// origin, including through the direct library capability API.
    pub(crate) fn check_evaluations(
        &self,
        checked: &CheckedHistoryStepRetirementMatrices,
    ) -> Result<(), V2Error> {
        self.check_key_digests(
            checked.target().legacy_bank_digest(),
            checked.evaluation_key_digests(),
        )
    }

    fn check_key_digests(
        &self,
        legacy_bank: [u8; 32],
        checked: &[Option<[u8; 32]>; 2],
    ) -> Result<(), V2Error> {
        if legacy_bank != self.legacy_bank || checked.iter().all(Option::is_none) {
            return Err(V2Error::Origin);
        }
        for (digest, key) in checked.iter().zip(&self.keys) {
            if digest.is_some_and(|digest| digest != key.digest()) {
                return Err(V2Error::Origin);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct RetirementOriginCertificate {
    legacy: LegacyOriginCertificate,
    reduction: Vec<u8>,
    evaluations: Vec<(CanonicalHistoryStepClassId, Vec<u8>)>,
}

fn retirement_error(error: impl core::fmt::Display) -> V2Error {
    V2Error::Retirement(error.to_string())
}

impl RetirementOriginCertificate {
    /// Framing only. Verification is a separate mandatory operation.
    pub fn new(
        legacy: LegacyOriginCertificate,
        reduction: Vec<u8>,
        evaluations: Vec<(CanonicalHistoryStepClassId, Vec<u8>)>,
    ) -> Result<Self, V2Error> {
        if reduction.is_empty()
            || reduction.len() > MAX_REDUCTION_BYTES
            || evaluations.is_empty()
            || evaluations.len() > 2
            || evaluations.windows(2).any(|pair| pair[0].0 >= pair[1].0)
            || evaluations.iter().any(|(_, bytes)| {
                bytes.is_empty() || bytes.len() > MAX_SPARSE_EVALUATION_PROOF_BYTES
            })
        {
            return Err(V2Error::Origin);
        }
        let certificate = Self {
            legacy,
            reduction,
            evaluations,
        };
        if certificate.wire_len() > MAX_RETIREMENT_ORIGIN_BYTES {
            return Err(V2Error::Origin);
        }
        Ok(certificate)
    }

    pub fn legacy_certificate(&self) -> &LegacyOriginCertificate {
        &self.legacy
    }

    pub fn verify(
        &self,
        legacy: &HistoryStepRuntime,
        next: &Bank,
        keys: &PinnedRetirementKeys,
    ) -> Result<VerifiedOrigin, V2Error> {
        if legacy.bank().digest() != keys.legacy_bank {
            return Err(V2Error::Origin);
        }
        noid_chain::consensus::pow::validate_pow(self.legacy.parent_header())
            .map_err(retirement_error)?;
        let target = HistoryStepRetirementTarget::new(
            next.config().schedule(),
            legacy.bank(),
            next.digest(),
        )
        .map_err(retirement_error)?;
        let terminal = decode_history_step_terminal(legacy, self.legacy.terminal_bytes())?;
        // This replay must never load legacy matrix rows. It leaves all
        // obligations pending, including the non-selected accumulated lane.
        let request = prepare_history_step_retirement(
            legacy,
            &terminal,
            self.legacy.parent_header(),
            self.legacy.epoch_header(),
            target,
        )
        .map_err(retirement_error)?;
        let reduction = HistoryStepRetirementReduction::decode_for(&request, &self.reduction)
            .map_err(retirement_error)?;
        let pending = request
            .verify_reduction(&reduction)
            .map_err(retirement_error)?;
        if pending.obligations().count() != self.evaluations.len() {
            return Err(V2Error::Origin);
        }
        let mut proofs = Vec::with_capacity(self.evaluations.len());
        for (obligation, (class, encoded)) in pending.obligations().zip(&self.evaluations) {
            if obligation.class_id() != *class {
                return Err(V2Error::Origin);
            }
            let key = &keys.keys[class.index()];
            proofs.push(
                SparseMatrixEvaluationProof::from_bytes(
                    key,
                    request.binding(),
                    obligation.claim(),
                    encoded,
                )
                .map_err(retirement_error)?,
            );
        }
        let evaluations: Vec<_> = self
            .evaluations
            .iter()
            .zip(&proofs)
            .map(|((class, _), proof)| HistoryStepRetirementEvaluation {
                class_id: *class,
                key: &keys.keys[class.index()],
                proof,
            })
            .collect();
        let checked = pending
            .verify_matrix_evaluations(&evaluations)
            .map_err(retirement_error)?;
        VerifiedOrigin::from_retirement(&request, checked, next, keys)
    }

    fn wire_len(&self) -> usize {
        8 + 4
            + self.legacy.to_bytes().len()
            + 2
            + self.reduction.len()
            + 1
            + self
                .evaluations
                .iter()
                .map(|(_, bytes)| 1 + 4 + bytes.len())
                .sum::<usize>()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.wire_len());
        let legacy = self.legacy.to_bytes();
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&(legacy.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&legacy);
        bytes.extend_from_slice(&(self.reduction.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&self.reduction);
        bytes.push(self.evaluations.len() as u8);
        for (class, proof) in &self.evaluations {
            bytes.push(class.wire_id());
            bytes.extend_from_slice(&(proof.len() as u32).to_le_bytes());
            bytes.extend_from_slice(proof);
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, V2Error> {
        if bytes.len() > MAX_RETIREMENT_ORIGIN_BYTES || !bytes.starts_with(MAGIC) {
            return Err(V2Error::Origin);
        }
        let mut reader = Reader { bytes, at: 8 };
        let legacy_len = u32::from_le_bytes(reader.take(4)?.try_into().unwrap()) as usize;
        if legacy_len > MAX_LEGACY_ORIGIN_BYTES {
            return Err(V2Error::Origin);
        }
        let legacy = LegacyOriginCertificate::from_bytes(reader.take(legacy_len)?)?;
        let reduction_len = u16::from_le_bytes(reader.take(2)?.try_into().unwrap()) as usize;
        if reduction_len == 0 || reduction_len > MAX_REDUCTION_BYTES {
            return Err(V2Error::Origin);
        }
        let reduction = reader.take(reduction_len)?;
        let count = reader.take(1)?[0] as usize;
        if !(1..=2).contains(&count) {
            return Err(V2Error::Origin);
        }
        // Preflight every span and exact EOF before cloning large proofs.
        let mut spans = Vec::with_capacity(count);
        for _ in 0..count {
            let class = CanonicalHistoryStepClassId::new(reader.take(1)?[0] as usize)
                .ok_or(V2Error::Origin)?;
            let length = u32::from_le_bytes(reader.take(4)?.try_into().unwrap()) as usize;
            if length == 0 || length > MAX_SPARSE_EVALUATION_PROOF_BYTES {
                return Err(V2Error::Origin);
            }
            spans.push((class, reader.take(length)?));
        }
        if reader.at != bytes.len() || spans.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
            return Err(V2Error::Origin);
        }
        Self::new(
            legacy,
            reduction.to_vec(),
            spans
                .into_iter()
                .map(|(class, proof)| (class, proof.to_vec()))
                .collect(),
        )
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], V2Error> {
        let end = self.at.checked_add(count).ok_or(V2Error::Origin)?;
        let value = self.bytes.get(self.at..end).ok_or(V2Error::Origin)?;
        self.at = end;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_evaluations_must_use_the_release_keys_for_each_live_class() {
        use noid_ivc_core::{
            field_r1cs::synthetic_satisfiable,
            matrix_claim::sparse_c1::{SparseEvaluationBudget, SparseMatrixProver},
        };
        let keys = [901, 902].map(|seed| {
            let matrix = synthetic_satisfiable(7, 7, seed).0;
            SparseMatrixProver::from_resident(
                &matrix,
                matrix.structural_statement_digest(),
                SparseEvaluationBudget {
                    max_padded_entries: 1 << 16,
                    max_planned_bytes: 64 << 20,
                },
            )
            .unwrap()
            .key()
            .clone()
        });
        // Tiny genuine preprocessing keys isolate the final pin check. Full
        // request coverage and reduction checks have independent tests.
        let pins = PinnedRetirementKeys {
            legacy_bank: [9; 32],
            keys,
        };
        let both = pins.keys.each_ref().map(|key| Some(key.digest()));
        assert_ne!(both[0], both[1]);
        for lanes in [both, [both[0], None], [None, both[1]]] {
            pins.check_key_digests([9; 32], &lanes).unwrap();
        }
        assert!(pins.check_key_digests([8; 32], &both).is_err());
        assert!(pins.check_key_digests([9; 32], &[None, None]).is_err());
        assert!(pins
            .check_key_digests([9; 32], &[both[1], both[0]])
            .is_err());
        for index in 0..2 {
            let mut substituted = both;
            substituted[index].as_mut().unwrap()[0] ^= 1;
            assert!(pins.check_key_digests([9; 32], &substituted).is_err());
        }
    }

    #[test]
    fn retirement_carrier_rejects_truncation_order_and_oversized_lengths() {
        let Some(activation) = noid_chain::consensus::params::V2_ACTIVATION_HEIGHT else {
            return;
        };
        let mut epoch = noid_chain::consensus::genesis_header();
        let mut parent = epoch;
        parent.height = activation - 1;
        epoch.height = noid_chain::consensus::tx_epoch_anchor_height_for_child(parent.height);
        let mut terminal = noid_chain::history_step::HistoryStepTerminalMetadata::new(
            parent.height,
            noid_chain::block_header::semantic_header_id(&parent),
            0,
        )
        .unwrap()
        .encode_prefix()
        .to_vec();
        terminal.push(1);
        // Deliberately invalid cryptographic material: framing never grants
        // a VerifiedOrigin. Real verification must replay all three proofs.
        let legacy = LegacyOriginCertificate::new(parent, epoch, terminal).unwrap();
        let small = CanonicalHistoryStepClassId::new(0).unwrap();
        let large = CanonicalHistoryStepClassId::new(1).unwrap();
        let certificate = RetirementOriginCertificate::new(
            legacy.clone(),
            vec![1; 45],
            vec![(small, vec![2; 64]), (large, vec![3; 128])],
        )
        .unwrap();
        let bytes = certificate.to_bytes();
        assert_eq!(
            RetirementOriginCertificate::from_bytes(&bytes)
                .unwrap()
                .to_bytes(),
            bytes
        );
        for cut in 0..bytes.len() {
            assert!(RetirementOriginCertificate::from_bytes(&bytes[..cut]).is_err());
        }
        let mut bad = bytes.clone();
        bad.push(0);
        assert!(RetirementOriginCertificate::from_bytes(&bad).is_err());
        let mut bad = bytes.clone();
        bad[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(RetirementOriginCertificate::from_bytes(&bad).is_err());
        let length_at = 12 + legacy.to_bytes().len();
        let mut bad = bytes.clone();
        bad[length_at..length_at + 2].copy_from_slice(&u16::MAX.to_le_bytes());
        assert!(RetirementOriginCertificate::from_bytes(&bad).is_err());
        let first = length_at + 2 + 45 + 1;
        let mut bad = bytes.clone();
        bad[first] = 2;
        assert!(RetirementOriginCertificate::from_bytes(&bad).is_err());
        let mut bad = bytes;
        bad[first + 1..first + 5].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(RetirementOriginCertificate::from_bytes(&bad).is_err());
        for evaluations in [
            vec![],
            vec![(small, vec![])],
            vec![(small, vec![1]), (small, vec![2])],
            vec![(large, vec![1]), (small, vec![2])],
        ] {
            assert!(
                RetirementOriginCertificate::new(legacy.clone(), vec![1], evaluations).is_err()
            );
        }
        assert!(
            RetirementOriginCertificate::from_bytes(&vec![0; MAX_RETIREMENT_ORIGIN_BYTES + 1])
                .is_err()
        );
    }
}

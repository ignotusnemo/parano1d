// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use super::*;
use noid_ivc_core::public_io::WitnessSlice;

/// The two v2 classes have their own wire ids and never select a legacy bank.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Class {
    Small = 0,
    Large = 1,
}

impl Class {
    pub const ALL: [Self; 2] = [Self::Small, Self::Large];
    pub const fn index(self) -> usize {
        self as usize
    }
    pub const fn wire_id(self) -> u8 {
        self as u8
    }
    pub fn from_wire(id: u8) -> Result<Self, V2Error> {
        match id {
            0 => Ok(Self::Small),
            1 => Ok(Self::Large),
            _ => Err(V2Error::Io),
        }
    }
}

/// Explicit joint recipe, not a choice of release capacity. Both entries use
/// the same fork schedule and interpreter, but their resource limits differ.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    classes: [V2Config; 2],
}

impl Config {
    pub fn new(small: V2Config, large: V2Config) -> Result<Self, V2Error> {
        if small.outer_m() != 23
            || large.outer_m() != 24
            || small.pages() >= large.pages()
            || !(matches!(large.pages(), 192 | 206 | 207 | 209 | 210 | 211 | 223 | 255)
                || large.native_header_capacity().is_some() && large.pages() == 176)
            || small.schedule() != large.schedule()
            || small.authorization_activation() != large.authorization_activation()
            || small.native_header_capacity().is_some() != large.native_header_capacity().is_some()
        {
            return Err(V2Error::Runtime);
        }
        Ok(Self {
            classes: [small, large],
        })
    }
    pub fn class(self, class: Class) -> V2Config {
        self.classes[class.index()]
    }
    pub fn for_pages(self, pages: usize) -> Result<Class, V2Error> {
        Class::ALL
            .into_iter()
            .find(|c| self.class(*c).pages() == pages)
            .ok_or(V2Error::Runtime)
    }
    pub fn activation_height(self) -> u64 {
        self.classes[0].activation_height()
    }
    pub fn schedule(self) -> noid_chain::consensus::forks::ForkSchedule {
        self.classes[0].schedule()
    }
    pub fn io_spec(self) -> PublicIoSpec {
        PublicIoSpec {
            io_slice: WitnessSlice {
                log2_len: 8,
                index: 1,
            },
            io_len: IO_LEN,
            claims: Vec::new(),
        }
    }
    pub(super) fn identity_bytes(self) -> Vec<u8> {
        self.classes
            .into_iter()
            .flat_map(V2Config::identity_bytes)
            .collect()
    }
}

pub(super) const BASE: usize = 0;
pub(super) const TIP_CLASS: usize = 1;
pub(super) const BANK: usize = 2;
pub(super) const MATRIX: usize = 4;
pub(super) const POST: usize = 8;
pub(super) const ORIGIN: usize = 12;
pub(super) const ORIGIN_ID: usize = 14;
pub(super) const ORIGIN_ACC: usize = 16;
pub(super) const POINT: usize = 26;
pub(super) const ACC: usize = 224;
pub(super) const IO_LEN: usize = ACC + 10;

#[derive(Clone, Copy)]
pub(super) struct Lane {
    pub point: usize,
    pub value: usize,
    pub live: usize,
}
impl Lane {
    pub fn for_class(class: Class) -> Self {
        match class {
            Class::Small => Self {
                point: POINT,
                value: 120,
                live: 122,
            },
            Class::Large => Self {
                point: 123,
                value: 221,
                live: 223,
            },
        }
    }
    pub fn point_len(self) -> usize {
        (self.value - self.point) / 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn common_layout_has_two_complete_matrix_lanes() {
        let mut next = POINT;
        for (class, m) in Class::ALL.into_iter().zip([23, 24]) {
            let lane = Lane::for_class(class);
            assert_eq!(lane.point, next);
            assert_eq!(lane.point_len(), 2 * m + 1);
            assert_eq!(lane.live, lane.value + 2);
            next = lane.live + 1;
        }
        assert_eq!(next, ACC);
        assert!(IO_LEN <= 256);
        assert!(Class::from_wire(2).is_err());
    }

    #[test]
    fn joint_recipe_rejects_swapped_shapes_and_mixed_schedules() {
        use noid_chain::consensus::forks::{ForkSchedule, V2Activation};
        let schedule = ForkSchedule::new(Some(5), V2Activation::new(10, 30)).unwrap();
        let later = ForkSchedule::new(Some(5), V2Activation::new(11, 30)).unwrap();
        let small = V2Config::new(23, 63, schedule).unwrap();
        let large = V2Config::new(24, 255, schedule).unwrap();
        let config = Config::new(small, large).unwrap();
        assert_eq!(config.for_pages(63).unwrap(), Class::Small);
        assert_eq!(config.for_pages(255).unwrap(), Class::Large);
        assert!(config.for_pages(25).is_err());
        assert!(Config::new(large, small).is_err());
        assert!(Config::new(V2Config::new(24, 63, schedule).unwrap(), large).is_err());
        assert!(Config::new(small, V2Config::new(24, 96, schedule).unwrap()).is_err());
        assert!(Config::new(small, V2Config::new(24, 255, later).unwrap()).is_err());
    }

    #[test]
    fn large_page_tradeoffs_are_pinned_separately_from_legacy_classes() {
        use noid_chain::consensus::forks::{ForkSchedule, V2Activation};
        let schedule = ForkSchedule::new(Some(5), V2Activation::new(10, 30)).unwrap();
        let small = V2Config::with_limits(23, 63, 504, 63, schedule).unwrap();
        let mut identities = std::collections::HashSet::new();
        for pages in [206, 207, 209, 210, 211, 223, 255] {
            let large = V2Config::with_limits(24, pages, 504, 63, schedule).unwrap();
            let config = Config::new(small, large).unwrap();
            assert_eq!(config.for_pages(pages).unwrap(), Class::Large);
            assert_eq!(config.for_pages(63).unwrap(), Class::Small);
            assert_eq!(config.class(Class::Large).contract_slots(), 63);
            assert_eq!(config.class(Class::Large).max_live_inputs(), 504);
            assert!(identities.insert(config.identity_bytes()));
        }
    }
}

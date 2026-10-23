// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use super::*;
use noid_ivc_core::public_io::WitnessSlice;

/// Stable wire identifiers for the three proof classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Class {
    Small = 0,
    Large = 1,
    Native = 2,
}

impl Class {
    pub const ALL: [Self; 3] = [Self::Small, Self::Large, Self::Native];
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
            2 => Ok(Self::Native),
            _ => Err(V2Error::Io),
        }
    }
}

/// Three resource profiles sharing one activation and interpreter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    classes: [V2Config; 3],
    fused_pins: bool,
    linear_rows: bool,
    product_aliases: bool,
    shared_m24: bool,
}

impl Config {
    pub fn new(small: V2Config, large: V2Config, native: V2Config) -> Result<Self, V2Error> {
        if small.authorization_activation().is_none()
            || small.outer_m() != 23
            || large.outer_m() != 24
            || small.pages() >= large.pages()
            || !(matches!(large.pages(), 192 | 206 | 207 | 209 | 210 | 211 | 223 | 255)
                || large.native_header_capacity().is_some() && large.pages() == 176)
            || small.schedule() != large.schedule()
            || small.authorization_activation() != large.authorization_activation()
            || small.native_header_capacity().is_some() != large.native_header_capacity().is_some()
            || native.outer_m() != 24
            || native.pages() != small.pages()
            || native.schedule() != small.schedule()
            || native.authorization_activation() != small.authorization_activation()
            || native.native_sequential_config().is_none()
        {
            return Err(V2Error::Runtime);
        }
        Ok(Self {
            classes: [small, large, native],
            fused_pins: false,
            linear_rows: false,
            product_aliases: false,
            shared_m24: false,
        })
    }
    pub fn with_fused_pins(mut self) -> Self {
        self.fused_pins = true;
        self
    }
    pub fn with_reused_linear_rows(mut self) -> Self {
        self.linear_rows = true;
        self
    }
    pub fn with_product_aliases(mut self) -> Self {
        self.product_aliases = true;
        self
    }
    pub fn with_shared_m24(mut self) -> Self {
        self.shared_m24 = true;
        self
    }
    pub fn shared_m24(self) -> bool {
        self.shared_m24
    }
    pub fn product_aliases(self) -> bool {
        self.product_aliases
    }
    pub fn reuses_linear_rows(self) -> bool {
        self.linear_rows
    }
    pub fn fused_pins(self) -> bool {
        self.fused_pins
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
                log2_len: 9,
                index: 1,
            },
            io_len: IO_LEN,
            claims: Vec::new(),
        }
    }
    pub(super) fn identity_bytes(self) -> Vec<u8> {
        let mut bytes: Vec<u8> = self
            .classes
            .into_iter()
            .flat_map(V2Config::identity_bytes)
            .collect();
        if self.fused_pins {
            bytes.extend_from_slice(b"fused-boolean-pins-v1");
        }
        if self.linear_rows {
            bytes.extend_from_slice(b"reused-linear-rows-v1");
        }
        if self.product_aliases {
            bytes.extend_from_slice(b"symbolic-product-aliases-v2");
        }
        if self.shared_m24 {
            bytes.extend_from_slice(b"shared-m24-parent-verifier-v1");
        }
        bytes
    }
}

pub(super) const BASE: usize = 0;
pub(super) const TIP_CLASS: usize = 1;
pub(super) const BANK: usize = 2;
pub(super) const MATRIX: usize = 4;
pub(super) const POST: usize = 10;
pub(super) const ORIGIN: usize = 16;
pub(super) const ORIGIN_ID: usize = 18;
pub(super) const ORIGIN_ACC: usize = 20;
pub(super) const POINT: usize = 30;
pub(super) const ACC: usize = 329;
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
                value: 124,
                live: 126,
            },
            Class::Large => Self {
                point: 127,
                value: 225,
                live: 227,
            },
            Class::Native => Self {
                point: 228,
                value: 326,
                live: 328,
            },
        }
    }
    pub fn point_len(self) -> usize {
        (self.value - self.point) / 2
    }
}

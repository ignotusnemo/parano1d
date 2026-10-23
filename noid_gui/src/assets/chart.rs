// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use super::live::Key;
use crate::market_data::{History, Price, MAX_BLOCKS};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct Point {
    pub height: u64,
    pub hash: String,
    pub price: Price,
}

#[derive(Debug)]
pub struct State {
    pub asset: Option<[u8; 32]>,
    pub points: Vec<Point>,
    pub history: Option<History>,
    pub loading: bool,
    pub error: Option<String>,
    pub span: u64,
    generation: u64,
    attempted: Option<Instant>,
    point_generation: u64,
    point_request: Option<(u64, Key)>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            asset: None,
            points: Vec::new(),
            history: None,
            loading: false,
            error: None,
            span: 120,
            generation: 0,
            attempted: None,
            point_generation: 0,
            point_request: None,
        }
    }
}

impl State {
    pub fn clear_remote(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.history = None;
        self.loading = false;
        self.error = None;
        self.attempted = None;
    }
    pub fn deactivate(&mut self) {
        if self.asset.is_some() {
            self.clear_remote();
            self.asset = None;
            self.points.clear();
            self.point_generation = self.point_generation.wrapping_add(1);
            self.point_request = None;
        }
    }
    pub fn observe(&mut self, asset: [u8; 32], key: &Key, price: Price) {
        if !price.valid() {
            return;
        }
        if self.asset != Some(asset) {
            self.deactivate();
            self.asset = Some(asset);
        }
        if self.points.last().is_some_and(|p| {
            p.height > key.height || p.height == key.height && p.hash != key.block_hash
        }) {
            self.points.retain(|p| p.height < key.height);
            self.clear_remote();
        }
        if self.points.last().is_none_or(|p| p.height != key.height) {
            self.points.push(Point {
                height: key.height,
                hash: key.block_hash.clone(),
                price,
            });
            if self.points.len() > MAX_BLOCKS {
                self.points.drain(..self.points.len() - MAX_BLOCKS);
            }
        }
    }
    pub fn begin_point(
        &mut self,
        asset: [u8; 32],
        key: &Key,
        price: Price,
    ) -> Option<(u64, Point)> {
        if self.asset != Some(asset) || self.points.is_empty() {
            self.observe(asset, key, price);
            return None;
        }
        let previous = self.points.last()?.clone();
        if previous.height == key.height && previous.hash == key.block_hash
            || self.point_request.is_some()
        {
            return None;
        }
        self.point_generation = self.point_generation.wrapping_add(1);
        self.point_request = Some((self.point_generation, key.clone()));
        Some((self.point_generation, previous))
    }
    pub fn finish_point(
        &mut self,
        generation: u64,
        asset: [u8; 32],
        key: &Key,
        price: Price,
        canonical: Result<bool, String>,
        current: bool,
    ) {
        if self.point_request.as_ref() != Some(&(generation, key.clone())) {
            return;
        }
        self.point_request = None;
        if !current || self.asset != Some(asset) {
            return;
        }
        if let Ok(canonical) = canonical {
            if !canonical {
                self.points.clear();
                self.clear_remote();
            }
            self.observe(asset, key, price);
        }
    }
    pub fn begin(&mut self, enabled: bool, key: &Key) -> Option<u64> {
        if !enabled
            || self.asset.is_none()
            || self.loading
            || self
                .history
                .as_ref()
                .is_some_and(|h| h.through.height == key.height && h.through.hash == key.block_hash)
            || self.attempted.is_some_and(|last| {
                last.elapsed() < Duration::from_secs(if self.error.is_some() { 30 } else { 5 })
            })
        {
            return None;
        }
        self.generation = self.generation.wrapping_add(1);
        self.loading = true;
        self.attempted = Some(Instant::now());
        Some(self.generation)
    }
    pub fn finish(&mut self, generation: u64, asset: [u8; 32], result: Result<History, String>) {
        if generation != self.generation || self.asset != Some(asset) || !self.loading {
            return;
        }
        self.loading = false;
        match result {
            Ok(history) => {
                self.history = Some(history);
                self.error = None;
            }
            Err(error) => self.error = Some(error),
        }
    }
}

//! Share identical ordered input blocks across permutation layers and folds.
//!
//! Every physical row keeps its equality weight. A group sums those weights
//! and evaluates the common relation once. The equivalence classes follow
//! exact input equality and ordered pairs, independently of Fiat-Shamir coins.

use super::*;
use std::collections::HashMap;

pub(super) struct Plan {
    source_rows: usize,
    representatives: Vec<u32>,
    pub layers: Vec<Layer>,
}

pub(super) struct Layer {
    edges: Vec<[u32; 2]>,
    source_rows: usize,
    #[cfg(test)]
    offsets: Vec<u32>,
    #[cfg(test)]
    positions: Vec<u32>,
}

impl Layer {
    fn new(ids: &[u32], edges: Vec<[u32; 2]>) -> Self {
        #[cfg(test)]
        let (offsets, positions) = {
            let mut offsets = vec![0u32; edges.len() + 1];
            for &id in ids {
                offsets[id as usize + 1] += 1;
            }
            for i in 1..offsets.len() {
                offsets[i] += offsets[i - 1];
            }
            let mut next = offsets[..edges.len()].to_vec();
            let mut positions = vec![0u32; ids.len()];
            for (position, &id) in ids.iter().enumerate() {
                positions[next[id as usize] as usize] = position as u32;
                next[id as usize] += 1;
            }
            (offsets, positions)
        };
        Self {
            edges,
            source_rows: ids.len(),
            #[cfg(test)]
            offsets,
            #[cfg(test)]
            positions,
        }
    }

    #[cfg(test)]
    fn weight(&self, group: usize, eq: &[F256], paired: bool) -> F256 {
        self.positions[self.offsets[group] as usize..self.offsets[group + 1] as usize]
            .iter()
            .fold(F256::ZERO, |sum, &position| {
                let i = position as usize;
                sum + if paired {
                    eq[2 * i] + eq[2 * i + 1]
                } else {
                    eq[i]
                }
            })
    }

    pub fn base_contribution(
        &self,
        round: usize,
        point: F256,
        eq: &[F256],
        columns: &[F256; STATE_SIZE],
        states: &[[F128; STATE_SIZE]],
    ) -> [F256; WALK_DEGREE + 1] {
        debug_assert_eq!(eq.len(), self.edges.len());
        let relation = self
            .edges
            .par_chunks(CONSTANT_PAIR_CHUNK)
            .enumerate()
            .map(|(chunk, edges)| {
                let mut result = [F256::ZERO; WALK_DEGREE];
                for (offset, &[a, b]) in edges.iter().enumerate() {
                    let a = states[a as usize];
                    let b = states[b as usize];
                    let weight = eq[chunk * CONSTANT_PAIR_CHUNK + offset];
                    let delta = std::array::from_fn(|lane| a[lane] + b[lane]);
                    let value =
                        weighted_base_relation_coefficients(round, weight, columns, &a, &delta);
                    for i in 0..WALK_DEGREE {
                        result[i] += value[i];
                    }
                }
                result
            })
            .reduce(
                || [F256::ZERO; WALK_DEGREE],
                |mut a, b| {
                    for i in 0..WALK_DEGREE {
                        a[i] += b[i];
                    }
                    a
                },
            );
        convolve_equality_factor(relation, F256::ONE + point)
    }

    pub fn wide_contribution(
        &self,
        round: usize,
        point: F256,
        eq: &[F256],
        columns: &[F256; STATE_SIZE],
        states: &[[F256; STATE_SIZE]],
    ) -> [F256; WALK_DEGREE + 1] {
        debug_assert_eq!(eq.len(), self.edges.len());
        let relation = self
            .edges
            .par_chunks(CONSTANT_PAIR_CHUNK)
            .enumerate()
            .map(|(chunk, edges)| {
                let mut result = [F256::ZERO; WALK_DEGREE];
                for (offset, &[a, b]) in edges.iter().enumerate() {
                    let a = states[a as usize];
                    let b = states[b as usize];
                    let weight = eq[chunk * CONSTANT_PAIR_CHUNK + offset];
                    let delta = std::array::from_fn(|lane| a[lane] + b[lane]);
                    let value =
                        weighted_wide_relation_coefficients(round, weight, columns, &a, &delta);
                    for i in 0..WALK_DEGREE {
                        result[i] += value[i];
                    }
                }
                result
            })
            .reduce(
                || [F256::ZERO; WALK_DEGREE],
                |mut a, b| {
                    for i in 0..WALK_DEGREE {
                        a[i] += b[i];
                    }
                    a
                },
            );
        convolve_equality_factor(relation, F256::ONE + point)
    }

    pub fn fold_base(
        &self,
        base: &[[F128; STATE_SIZE]],
        out: &mut Vec<[F256; STATE_SIZE]>,
        r: F256,
    ) {
        out.clear();
        out.par_extend(self.edges.par_iter().map(|&[a, b]| {
            let a = base[a as usize];
            let b = base[b as usize];
            std::array::from_fn(|i| F256::from_base(a[i]) + scale_base(r, a[i] + b[i]))
        }));
    }

    pub fn fold_wide(
        &self,
        values: &mut Vec<[F256; STATE_SIZE]>,
        scratch: &mut Vec<[F256; STATE_SIZE]>,
        r: F256,
    ) {
        scratch.clear();
        scratch.par_extend(self.edges.par_iter().map(|&[a, b]| {
            let a = values[a as usize];
            let b = values[b as usize];
            std::array::from_fn(|i| a[i] + r * (a[i] + b[i]))
        }));
        std::mem::swap(values, scratch);
    }
}

impl Plan {
    /// Equality mass of every distinct block at each fold coordinate.
    /// Descending through ordered pairs sums all physical occurrences. The
    /// first coordinate of each block is kept for the sumcheck polynomial.
    pub fn equality_weights(&self, point: &[F256]) -> Vec<Vec<F256>> {
        assert_eq!(point.len(), self.layers.len());
        let mut result: Vec<Vec<F256>> = self
            .layers
            .iter()
            .map(|layer| vec![F256::ZERO; layer.edges.len()])
            .collect();
        result.last_mut().expect("nonempty plan")[0] = F256::ONE;
        for level in (1..self.layers.len()).rev() {
            let (lower, upper) = result.split_at_mut(level);
            let lower = &mut lower[level - 1];
            for (&[a, b], &weight) in self.layers[level].edges.iter().zip(&upper[0]) {
                if a == b {
                    lower[a as usize] += weight;
                } else {
                    let high = weight * point[level];
                    lower[a as usize] += weight + high;
                    lower[b as usize] += high;
                }
            }
        }
        result
    }

    pub fn new(columns: &[Vec<F128>; STATE_SIZE]) -> Option<Self> {
        let n = columns[0].len();
        if n < 16 || n > u32::MAX as usize {
            return None;
        }
        let mut rows = HashMap::new();
        let mut representatives = Vec::new();
        let row_ids: Vec<_> = (0..n)
            .map(|i| {
                let key: [F128; STATE_SIZE] = std::array::from_fn(|lane| columns[lane][i]);
                let next = representatives.len() as u32;
                *rows.entry(key).or_insert_with(|| {
                    representatives.push(i as u32);
                    next
                })
            })
            .collect();
        drop(rows);
        let mut map = HashMap::new();
        let mut edges = Vec::new();
        let mut ids = Vec::with_capacity(n / 2);
        for pair in row_ids.chunks_exact(2) {
            let key = [pair[0], pair[1]];
            let next = edges.len() as u32;
            let id = *map.entry(key).or_insert_with(|| {
                edges.push(key);
                next
            });
            ids.push(id);
        }
        drop(map);
        if representatives.len() * 10 > n * 9 && edges.len() * 10 > ids.len() * 9 {
            return None;
        }
        let mut layers = Vec::with_capacity(n.ilog2() as usize);
        loop {
            layers.push(Layer::new(&ids, edges));
            if ids.len() == 1 {
                break;
            }
            let mut map = HashMap::new();
            edges = Vec::new();
            ids = ids
                .chunks_exact(2)
                .map(|pair| {
                    let key = [pair[0], pair[1]];
                    let next = edges.len() as u32;
                    *map.entry(key).or_insert_with(|| {
                        edges.push(key);
                        next
                    })
                })
                .collect();
        }
        Some(Self {
            source_rows: n,
            representatives,
            layers,
        })
    }

    pub fn initial_rows(&self, columns: &[Vec<F128>; STATE_SIZE]) -> Vec<[F128; STATE_SIZE]> {
        self.representatives
            .par_iter()
            .map(|&row| std::array::from_fn(|lane| columns[lane][row as usize]))
            .collect()
    }

    pub fn counts(&self) -> Vec<(usize, usize)> {
        std::iter::once((self.source_rows, self.representatives.len()))
            .chain(
                self.layers
                    .iter()
                    .map(|layer| (layer.source_rows, layer.edges.len())),
            )
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dag_equality_masses_match_every_original_occurrence() {
        let columns: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|lane| {
            (0..512)
                .map(|i| F128::new((((i / 8) % 3) * 8 + i % 8 + 1) as u64, lane as u64))
                .collect()
        });
        let plan = Plan::new(&columns).unwrap();
        for mode in 0..3 {
            let point: Vec<_> = (0..9)
                .map(|i| match mode {
                    0 => F256::new(F128::new(i + 3, i + 11), F128::new(i + 29, i + 41)),
                    1 => F256::ZERO,
                    _ => F256::ONE,
                })
                .collect();
            let weights = plan.equality_weights(&point);
            for (level, layer) in plan.layers.iter().enumerate() {
                let eq = build_eq_table(&point[level + 1..]);
                for group in 0..layer.edges.len() {
                    assert_eq!(weights[level][group], layer.weight(group, &eq, false));
                }
                assert_eq!(
                    weights[level]
                        .iter()
                        .copied()
                        .fold(F256::ZERO, |a, b| a + b),
                    F256::ONE
                );
            }
        }
    }
}

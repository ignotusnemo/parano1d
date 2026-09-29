use super::*;

pub(super) struct Chain {
    pub state: ChainState,
    pub accumulator: ChainAccumulator,
    headers: Vec<BlockHeader>,
    outputs: BTreeSet<u32>,
    cursor: u32,
    distributed_cursor: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_builder_uses_the_fork_parent_as_asert_anchor() {
        let schedule = ForkSchedule::new(
            Some(5),
            noid_chain::consensus::forks::V2Activation::new(10, 30),
        )
        .unwrap();
        let mut chain = Chain::empty();
        let genesis = *chain.parent();
        for height in 1..=9 {
            let mut header = genesis;
            header.height = height;
            header.timestamp += 20 * height;
            chain.headers.push(header);
        }
        let parent = chain.headers.last_mut().unwrap();
        let mut carry = 0;
        for byte in parent.difficulty_target.iter_mut().rev() {
            let next = (*byte & 1) << 7;
            *byte = (*byte >> 1) | carry;
            carry = next;
        }
        let expected = parent.difficulty_target;
        assert_ne!(expected, genesis.difficulty_target);
        let (block, _) = chain.build(&[], schedule).unwrap();
        assert_eq!(block.header.height, 10);
        assert_eq!(block.header.timestamp, chain.parent().timestamp + 30);
        assert_eq!(block.header.difficulty_target, expected);
    }

    #[test]
    fn freezing_fixture_distinguishes_tip_and_child_epoch_anchors() {
        for activation in [
            10,
            145,
            noid_chain::consensus::params::MAINNET_V2_ACTIVATION_HEIGHT,
        ] {
            let schedule = ForkSchedule::new(
                Some(5),
                noid_chain::consensus::forks::V2Activation::new(activation, 30),
            )
            .unwrap();
            let config = v2::V2Config::with_limits(23, 63, 504, 63, schedule).unwrap();
            let (first, first_epoch) = Chain::for_matrix_freezing(config, 0).unwrap();
            let (second, second_epoch) = Chain::for_matrix_freezing(config, 1).unwrap();
            assert_eq!(first.parent().height + 1, activation);
            assert_ne!(
                first.accumulator.tip_semantic_id,
                second.accumulator.tip_semantic_id
            );
            first
                .accumulator
                .validate_local_header_boundary(first.parent(), &first_epoch)
                .unwrap();
            second
                .accumulator
                .validate_local_header_boundary(second.parent(), &second_epoch)
                .unwrap();
            let (block, _) = first.build(&[], schedule).unwrap();
            let next = first
                .accumulator
                .advance(first.parent(), &block.header)
                .unwrap();
            next.validate_local_header_boundary(&block.header, &first.epoch())
                .unwrap();
            if activation == 145 {
                assert_eq!(first_epoch.height, 0);
                assert_eq!(first.epoch().height, 144);
                assert_ne!(first.accumulator.epoch_anchor_id, next.epoch_anchor_id);
            }
        }
    }
}
impl Chain {
    fn empty() -> Self {
        Self {
            state: ChainState::new(),
            accumulator: noid_recursive::genesis_accumulator(),
            headers: vec![noid_chain::consensus::genesis_header()],
            outputs: BTreeSet::new(),
            cursor: 2_000_000,
            distributed_cursor: None,
        }
    }

    /// Hypothetical boundary for matrix generation before the scheduled fork.
    /// These headers are witness data only, not a proved or accepted history.
    pub(super) fn for_matrix_freezing(
        config: v2::V2Config,
        variant: u64,
    ) -> Result<(Self, BlockHeader)> {
        let mut chain = Self::empty();
        let genesis = *chain.parent();
        let parent_height = config.activation_height() - 1;
        // The source-pinned mainnet height is small enough for a dense header
        // fixture; reject unbounded allocations if reused by another probe.
        if parent_height > 1_000_000 || variant > 1 {
            return Err("matrix-freezing fixture bound".into());
        }
        for height in 1..=parent_height {
            let mut header = genesis;
            header.height = height;
            header.timestamp += height * 20 + variant;
            header.nonce = u128::from(variant);
            chain.headers.push(header);
        }
        let parent = chain.parent();
        let epoch = chain.headers
            [noid_chain::consensus::tx_epoch_anchor_height_for_child(parent.height) as usize];
        chain.accumulator = ChainAccumulator {
            height: parent.height,
            tip_semantic_id: noid_chain::block_header::semantic_header_id(parent),
            state_root: parent.state_root,
            log_slots: parent.log_slots,
            active_slot_count: parent.active_slot_count,
            alloc_counter: parent.alloc_counter,
            epoch_anchor_id: noid_chain::hash_block_header(&epoch),
        };
        chain
            .accumulator
            .validate_local_header_boundary(chain.parent(), &epoch)
            .map_err(err)?;
        Ok((chain, epoch))
    }

    /// Reconstruct a benchmark's parent State from bounded block bodies.
    /// The receiver first verifies its complete endpoint terminal, then
    /// checks this replay's parent ID against that authenticated endpoint.
    pub fn replay_for_receiver(
        fixtures: &Path,
        output: &Path,
        config: v2::V2Config,
        height: u64,
    ) -> Result<Self> {
        let mut chain = Self::empty();
        for next in 1..=height {
            let root = if next < config.activation_height() {
                fixtures
            } else {
                output
            };
            let block = Block::from_bytes(&proof::bounded(
                &root.join(format!("h{next:06}.block")),
                16 * 1024 * 1024,
            )?)
            .map_err(err)?;
            if block.header.height != next {
                return Err("receiver fixture height mismatch".into());
            }
            chain.check_native(&block, config.schedule())?;
            let end = chain
                .accumulator
                .advance(chain.parent(), &block.header)
                .map_err(err)?;
            noid_chain::materialize_accepted_block_state(&mut chain.state, &block).map_err(err)?;
            chain.accept(block, end);
        }
        Ok(chain)
    }
    pub fn parent(&self) -> &BlockHeader {
        self.headers.last().unwrap()
    }
    pub fn epoch(&self) -> BlockHeader {
        self.headers[(self.accumulator.height / noid_chain::consensus::params::TX_EPOCH_BLOCKS
            * noid_chain::consensus::params::TX_EPOCH_BLOCKS) as usize]
    }
    pub fn epoch_id(&self) -> [u8; 32] {
        noid_chain::hash_block_header(&self.epoch())
    }
    fn timestamps(&self) -> Vec<u64> {
        self.headers
            .iter()
            .rev()
            .take(11)
            .map(|h| h.timestamp)
            .collect()
    }
    fn counts(&self) -> Vec<u64> {
        noid_chain::consensus::slot_expansion::finalized_expansion_window(self.parent().height)
            .map(|(start, end)| {
                self.headers[start as usize..=end as usize]
                    .iter()
                    .map(|h| h.active_slot_count)
                    .collect()
            })
            .unwrap_or_default()
    }
    fn anchor(&self) -> AnchorInfo {
        self.anchor_with_schedule(noid_chain::consensus::forks::ACTIVE_SCHEDULE)
    }
    fn anchor_with_schedule(&self, schedule: ForkSchedule) -> AnchorInfo {
        let h = self.headers[noid_chain::consensus::header::asert_anchor_height_with_schedule(
            self.parent().height,
            schedule,
        ) as usize];
        AnchorInfo {
            anchor_height: h.height,
            anchor_timestamp: h.timestamp,
            anchor_target: h.difficulty_target,
        }
    }
    pub fn load(
        settings: &Settings,
        runtime: &noid_recursive::HistoryStepRuntime,
    ) -> Result<(Self, noid_recursive::HistoryStepTerminal)> {
        let mut chain = Self::empty();
        let mut tip = None;
        for height in 1..settings.config.activation_height() {
            let block = Block::from_bytes(&proof::bounded(
                &settings.fixtures.join(format!("h{height:06}.block")),
                16 * 1024 * 1024,
            )?)
            .map_err(err)?;
            chain.check_native(&block, settings.config.schedule())?;
            let bytes = proof::bounded(
                &settings.fixtures.join(format!("h{height:06}.terminal")),
                legacy::history_step_terminal_max_wire_bytes(runtime).map_err(err)?,
            )?;
            let start = Instant::now();
            let terminal = legacy::decode_history_step_terminal(runtime, &bytes).map_err(err)?;
            let accepted = legacy::verify_history_step_terminal(
                runtime,
                &terminal,
                &block.header,
                &chain.epoch(),
            )
            .map_err(err)?;
            let expected = chain
                .accumulator
                .advance(chain.parent(), &block.header)
                .map_err(err)?;
            if accepted.accumulator() != &expected {
                return Err("legacy boundary mismatch".into());
            }
            noid_chain::materialize_accepted_block_state(&mut chain.state, &block).map_err(err)?;
            println!(
                "{}",
                json!({"phase":"reverify_legacy", "height":height,
                "verify_apply_ms":elapsed(start),"terminal_bytes":bytes.len(),"memory":memory()})
            );
            chain.accept(block, expected);
            tip = Some(terminal);
        }
        Ok((chain, tip.ok_or("legacy tip required")?))
    }
    pub fn check_native(&self, block: &Block, schedule: ForkSchedule) -> Result<()> {
        noid_chain::consensus::validation::validate_block_checks_with_schedule(
            block,
            self.parent(),
            &self.timestamps(),
            &self.counts(),
            Some(block.header.timestamp),
            &self.anchor_with_schedule(schedule),
            true,
            schedule,
        )
        .map_err(err)?;
        noid_chain::consensus::validate_block_epoch_anchors(
            block,
            self.epoch_id(),
            noid_chain::hash_block_header(self.parent()),
        )
        .map_err(err)
    }
    pub fn accept(&mut self, block: Block, accumulator: ChainAccumulator) {
        for tx in &block.transactions {
            for (_, input) in tx.body.live_inputs() {
                self.outputs.remove(&input.slot_index);
            }
            for (_, output) in tx.body.live_outputs() {
                self.outputs.insert(output.slot_index);
            }
        }
        self.accumulator = accumulator;
        self.headers.push(block.header);
    }
    pub fn ordinary_slots(&self) -> Vec<u32> {
        self.slots_owned_by(address(1))
    }
    pub fn slots_owned_by(&self, owner: Address) -> Vec<u32> {
        let owner = owner.as_fields();
        self.outputs
            .iter()
            .copied()
            .filter(|slot| {
                let value = self.state.state.slot(*slot);
                !value.is_empty() && [value.owner_hi, value.owner_lo] == owner
            })
            .collect()
    }
    pub fn input_slot(&self, slot: u32) -> Result<TxInput> {
        let value = self.state.state.slot(slot);
        if value.is_empty() {
            return Err("missing fixture input".into());
        }
        Ok(TxInput {
            slot_index: slot,
            amount: value.amount(),
            creation_id: value.creation_id(),
        })
    }
    pub fn empty_slots<const N: usize>(&mut self) -> Result<[u32; N]> {
        let mut slots = [0; N];
        for slot in &mut slots {
            loop {
                if let Some(cursor) = self.distributed_cursor.as_mut() {
                    // Cover all 256 segments of the authenticated depth-24
                    // fixture without injecting State or changing its root.
                    let value = ((*cursor % 256) << 16) | (4096 + *cursor / 256);
                    *cursor = cursor.checked_add(1).ok_or("distributed cursor overflow")?;
                    if *cursor / 256 >= 60_000 || self.parent().log_slots < 24 {
                        return Err("distributed fixture slot range".into());
                    }
                    if self.state.state.slot(value).is_empty() {
                        *slot = value;
                        break;
                    }
                    continue;
                }
                if u64::from(self.cursor) >= 1u64 << self.parent().log_slots {
                    return Err("fixture slot range exhausted".into());
                }
                let value = self.cursor;
                self.cursor = self.cursor.checked_add(1).ok_or("slot cursor overflow")?;
                if self.state.state.slot(value).is_empty() {
                    *slot = value;
                    break;
                }
            }
        }
        Ok(slots)
    }
    pub fn distribute_outputs(&mut self) {
        self.distributed_cursor = Some(0);
    }
    pub fn fee(&self, outputs: u64) -> u64 {
        noid_chain::consensus::fee_breakdown(
            1,
            outputs,
            self.parent().active_slot_count,
            self.parent().log_slots,
        )
        .required_total
        .max(10_000)
    }
    pub fn input<const PAGES: usize>(
        &self,
        block: &Block,
        batch: &Batch,
        ghost: &PreparedHistoryStepGhostAuthorization,
        config: v2::V2Config,
    ) -> Result<noid_recursive::HistoryStepBlockInput<PAGES>> {
        noid_block::candidate_history::prepare_candidate_input(
            block,
            noid_block::HistoryStepPreparationContext {
                parent_header: self.parent(),
                tx_epoch_anchor_header: &self.epoch(),
                parent_state: &self.state,
                start_accumulator: &self.accumulator,
                previous_timestamps: &self.timestamps(),
                finalized_active_counts: &self.counts(),
                asert_anchor: &self.anchor_with_schedule(config.schedule()),
                local_time: block.header.timestamp,
            },
            batch.proofs.clone(),
            ghost,
            &batch.openings,
            config,
        )
        .map_err(err)
    }

    pub fn legacy_empty_input(
        &self,
        block: Block,
        ghost: &PreparedHistoryStepGhostAuthorization,
    ) -> Result<noid_recursive::HistoryStepBlockInput<25>> {
        let end = self
            .accumulator
            .advance(self.parent(), &block.header)
            .map_err(err)?;
        let local_time = block.header.timestamp;
        noid_block::prepare_history_step_input_witness::<25>(
            block,
            noid_block::HistoryStepPreparationContext {
                parent_header: self.parent(),
                tx_epoch_anchor_header: &self.epoch(),
                parent_state: &self.state,
                start_accumulator: &self.accumulator,
                previous_timestamps: &self.timestamps(),
                finalized_active_counts: &self.counts(),
                asert_anchor: &self.anchor(),
                local_time,
            },
            Vec::new(),
            ghost,
        )
        .map_err(err)?
        .finish_template(&self.accumulator, &end)
        .map(|(_, input)| input)
        .map_err(err)
    }
    /// Measurement fixture constructor. Uses the real native transitions in
    /// fixed input order and checks the complete result again before proving.
    /// Its per-page rooting cost is recorded separately from HistoryStep.
    pub fn build(&self, pages: &[TxPage], schedule: ForkSchedule) -> Result<(Block, ChainState)> {
        use noid_chain::consensus::development_allocation::{
            development_allocation_with_schedule, O1_NETWORK_FUND_ADDRESS, PARANO1D_LAB_ADDRESS,
        };
        let height = self.parent().height + 1;
        let mut state = self.state.clone();
        let depth = noid_chain::consensus::expected_child_log_slots(
            self.parent().height,
            self.parent().log_slots,
            &self.counts(),
        );
        while state.state.log_slots() < depth as usize {
            state.expand_one();
        }
        let allocation =
            development_allocation_with_schedule(height, depth, schedule).map_err(err)?;
        let mut reserved: BTreeSet<u32> = pages
            .iter()
            .flat_map(|p| {
                p.body
                    .live_inputs()
                    .map(|(_, v)| v.slot_index)
                    .chain(p.body.live_outputs().map(|(_, v)| v.slot_index))
            })
            .collect();
        // Keep system outputs in the already touched fixture segment where possible.
        let mut cursor = 1_990_000u32;
        let mut slot = || -> Result<u32> {
            loop {
                let s = cursor;
                cursor = cursor.checked_add(1).ok_or("system slot range")?;
                if u64::from(s) >= 1u64 << depth {
                    return Err("no system slot".into());
                }
                if !reserved.contains(&s) && state.state.slot(s).is_empty() {
                    reserved.insert(s);
                    return Ok(s);
                }
            }
        };
        let fees: u128 = pages
            .iter()
            .map(|p| {
                let burned = noid_chain::consensus::fee_breakdown(
                    p.body.live_input_count() as u64,
                    p.body.live_output_count() as u64,
                    self.parent().active_slot_count,
                    self.parent().log_slots,
                )
                .burned;
                u128::from(p.body.fee.saturating_sub(burned))
            })
            .sum();
        let anchor = noid_chain::hash_block_header(self.parent());
        let mint = |outputs: [TxOutput; 2], bitmap| {
            Transaction::new(TxBody {
                epoch_anchor: anchor,
                fee: 0,
                input_owner: Address([0; 32]),
                inputs: [TxInput::dummy(); TX_INPUTS],
                outputs,
                validity_bitmap: bitmap,
                is_coinbase: true,
            })
        };
        let mut transactions = vec![mint(
            [
                TxOutput {
                    slot_index: slot()?,
                    amount: (u128::from(allocation.miner_subsidy) + fees).min(u128::from(u64::MAX))
                        as u64,
                    owner: address(1),
                },
                TxOutput::dummy(),
            ],
            output_bitmap_bit(0),
        )];
        if let Some(amount) = allocation.payout_each {
            transactions.push(mint(
                [
                    TxOutput {
                        slot_index: slot()?,
                        amount,
                        owner: O1_NETWORK_FUND_ADDRESS,
                    },
                    TxOutput {
                        slot_index: slot()?,
                        amount,
                        owner: PARANO1D_LAB_ADDRESS,
                    },
                ],
                output_bitmap_bit(0) | output_bitmap_bit(1),
            ));
        }
        transactions.extend(pages.iter().map(|p| Transaction::new(p.body.clone())));
        for tx in &transactions {
            noid_chain::state::apply_tx_at(&mut state, &tx.body, height).map_err(err)?;
        }
        let timestamp = self.parent().timestamp + schedule.block_time(height);
        let a = self.anchor_with_schedule(schedule);
        let header = BlockHeader {
            prev_block_hash: anchor,
            state_root: state.state_root(),
            tx_root: noid_chain::compute_tx_root(&transactions),
            timestamp,
            height,
            miner_address: address(1),
            nonce: 0,
            difficulty_target: noid_chain::consensus::difficulty::next_target_with_schedule(
                a.anchor_height,
                a.anchor_timestamp,
                &a.anchor_target,
                height,
                self.parent().timestamp,
                timestamp,
                schedule,
            ),
            log_slots: depth,
            active_slot_count: state.active_slot_count,
            alloc_counter: state.alloc_counter,
        };
        Ok((
            Block {
                header,
                transactions,
            },
            state,
        ))
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Deterministic native wallet plans from the current verified local State.

use crate::{
    native_types::*,
    types::WalletUtxoInfo,
    wallet_ops::{WalletNativeContext, WalletNativeIntent, WalletNativeProofRequest},
    wallet_submit::{collect_empty_slot_hints, next_user_epoch_anchor},
};
use noid_chain::{
    mempool::{trade_policy_resources, BlockSelectionBudget, NativeResourceUsage},
    storage::{native_payloads::NativeAssetLookup, MdbxChainContext},
};
use noid_poseidon2b::primitives::Address;
use noid_tx::{
    native_assets::{
        financial::{FinancialOperation, NativeParentRef},
        launch::{launch_supply_from_whole, LaunchDefinition, LaunchOpening, LaunchSide},
        nft_market::{ListingDefinition, ListingState, NftMarketOpening, NFT_FEE_CREDIT},
        trade::{
            sequencing::{SequencingPlan, TradeBoundary},
            TradeIntent, TradePolicy,
        },
        transition::{NativeContext, NativeInputClaim, NativeOperation, NativeOutputClaim},
        wire::NativeIntent,
        *,
    },
    TxInput, TxOutput,
};
use std::collections::{BTreeMap, HashSet};

type Result<T> = std::result::Result<T, String>;

pub(super) struct Prepared {
    pub proof: WalletNativeProofRequest,
    pub review: NativeWalletPreview,
}

struct Funding {
    inputs: Vec<NativeInputClaim>,
    fee: u64,
    change: Option<u64>,
}

struct Planner<'a> {
    chain: &'a MdbxChainContext,
    context: WalletNativeContext,
    reserved: HashSet<u32>,
    cash: Vec<NativeInputClaim>,
    floor: u64,
    seed: u64,
}

fn integer(value: &str, zero: bool) -> Result<u64> {
    if value.is_empty()
        || value.len() > 20
        || !value.bytes().all(|b| b.is_ascii_digit())
        || value.len() > 1 && value.starts_with('0')
    {
        return Err("native amounts require canonical decimal integers".into());
    }
    let number = value
        .parse::<u64>()
        .map_err(|_| "native amount exceeds u64")?;
    if !zero && number == 0 {
        return Err("native amount must be positive".into());
    }
    Ok(number)
}

fn hash(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64 {
        return Err("native identifier requires64 hexadecimal characters".into());
    }
    let mut bytes = [0; 32];
    hex::decode_to_slice(value, &mut bytes).map_err(|_| "invalid native identifier")?;
    Ok(bytes)
}

fn noid_effect(review: &mut NativeWalletPreview, spent: u128, received: u128) {
    review.noid_debit_micronoid = spent.saturating_sub(received).to_string();
    review.noid_credit_micronoid = received.saturating_sub(spent).to_string();
}

impl Planner<'_> {
    fn height(&self) -> u64 {
        self.context.parent.height + 1
    }
    fn fee(&self, inputs: usize, outputs: usize, financial: bool) -> Result<u64> {
        let fee = noid_chain::consensus::fee_breakdown(
            inputs as u64,
            outputs as u64,
            self.context.parent.active_slot_count,
            self.context.parent.log_slots,
        )
        .required_total;
        if financial && self.floor > fee {
            return Err("the current relay floor exceeds the native financial fee".into());
        }
        Ok(if financial { fee } else { fee.max(self.floor) })
    }
    fn funding(
        &self,
        native_inputs: usize,
        native_outputs: usize,
        debit: u64,
        credit: u64,
        financial: bool,
    ) -> Result<Funding> {
        let mut inputs = Vec::new();
        let mut total = u128::from(credit);
        for next in self.cash.iter().map(Some).chain(std::iter::once(None)) {
            let available = total.checked_sub(u128::from(debit));
            let plain = self.fee(native_inputs + inputs.len(), native_outputs, financial)?;
            let changed = self.fee(native_inputs + inputs.len(), native_outputs + 1, financial)?;
            if available == Some(u128::from(plain)) && native_outputs != 0 {
                return Ok(Funding {
                    inputs,
                    fee: plain,
                    change: None,
                });
            }
            if let Some(amount) = available.filter(|amount| *amount > u128::from(changed)) {
                let change = u64::try_from(amount - u128::from(changed))
                    .map_err(|_| "native change overflow")?;
                return Ok(Funding {
                    inputs,
                    fee: changed,
                    change: Some(change),
                });
            }
            let Some(next) = next else {
                break;
            };
            inputs.push(*next);
            total += u128::from(next.input.amount);
            if inputs.len() + native_inputs >= noid_tx::MAX_PAGED_SPEND_INPUTS {
                break;
            }
        }
        Err("insufficient spendable NOID for the native operation and its fee".into())
    }
    fn slots(&self, count: usize) -> Result<Vec<u32>> {
        let slots = collect_empty_slot_hints(self.chain, &self.reserved, self.seed, count)?;
        if slots.len() != count {
            return Err("not enough empty native output slots".into());
        }
        Ok(slots)
    }
    fn opening(&self, lookup: NativeAssetLookup) -> Result<NativeOpening> {
        let root = self
            .chain
            .store
            .native_asset_root(lookup)
            .map_err(|e| e.to_string())?
            .ok_or("native object is not present in the current State")?;
        self.chain
            .store
            .native_payload(root)
            .map_err(|e| e.to_string())?
            .map(|r| r.opening)
            .ok_or_else(|| "native terms are unavailable".into())
    }
    fn claim(&self, opening: NativeOpening) -> Result<NativeInputClaim> {
        let root = opening.root();
        let page = self
            .chain
            .store
            .get_verified_utxos_by_owner(&root.0)
            .map_err(|e| e.to_string())?;
        let live: Vec<_> = page
            .utxos
            .into_iter()
            .filter(|u| native_sequence(u.creation_id).is_ok())
            .collect();
        if live.len() != 1 {
            return Err("native object does not have one current carrier".into());
        }
        let u = live[0];
        if self.reserved.contains(&u.slot_index) {
            return Err("native object is reserved by a pending operation".into());
        }
        let input = TxInput {
            slot_index: u.slot_index,
            amount: u.amount,
            creation_id: u.creation_id,
        };
        opening
            .check_input(&input, root, self.height())
            .map_err(|e| e.to_string())?;
        Ok(NativeInputClaim {
            input,
            root,
            opening: Some(opening),
        })
    }
    fn tokens(&self, asset: AssetId, units: u64) -> Result<(Vec<NativeInputClaim>, u64)> {
        let mut cursor = None;
        let mut choices = Vec::new();
        let mut scanned = 0usize;
        loop {
            let page = self
                .chain
                .store
                .native_wallet_page(self.context.owner, cursor, 128)
                .map_err(|e| e.to_string())?;
            if page.height != self.context.parent.height
                || page.tip_hash != noid_chain::block_id(&self.context.parent)
            {
                return Err("native State changed during planning".into());
            }
            for item in page.items {
                scanned += 1;
                if scanned > 16_384 {
                    return Err("native source lookup limit reached".into());
                }
                if let NativeOpening::TokenBalance(balance) = item.opening {
                    if balance.asset == asset
                        && balance.unlock_height <= self.height()
                        && !self.reserved.contains(&item.carrier.slot_index)
                    {
                        choices.push((
                            balance.units,
                            NativeInputClaim {
                                input: TxInput {
                                    slot_index: item.carrier.slot_index,
                                    amount: item.carrier.amount,
                                    creation_id: item.carrier.creation_id,
                                },
                                root: Address(item.root),
                                opening: Some(item.opening),
                            },
                        ));
                    }
                }
            }
            cursor = page.next;
            if cursor.is_none() {
                break;
            }
        }
        choices.sort_by_key(|(units, claim)| (std::cmp::Reverse(*units), claim.input.slot_index));
        let mut selected = Vec::new();
        let mut total = 0u64;
        for (amount, claim) in choices {
            total = total
                .checked_add(amount)
                .ok_or("native token balance overflow")?;
            selected.push(claim);
            if total >= units {
                return Ok((selected, total - units));
            }
        }
        Err("insufficient unlocked token balance".into())
    }
    fn operation(
        &self,
        operation: NativeOperation,
        inputs: Vec<NativeInputClaim>,
        outputs: Vec<NativeOutputClaim>,
        fee: u64,
        extra: Vec<NativeOpening>,
    ) -> Result<WalletNativeIntent> {
        let context = NativeContext {
            chain: noid_chain::state::native_assets::native_chain_id(),
            height: self.height(),
            authority: self.context.owner,
            fee,
        };
        let intent = if let NativeOperation::Financial(financial) = operation {
            let map: BTreeMap<_, _> = inputs
                .iter()
                .filter_map(|i| i.opening)
                .chain(outputs.iter().filter_map(|o| o.opening))
                .chain(extra)
                .map(|o| (o.root().0, o))
                .collect();
            NativeIntent::from_financial_claims(
                &context,
                self.context.epoch_anchor,
                financial,
                self.context.round()?,
                inputs,
                outputs,
                |root| {
                    map.get(&root.0).copied().or_else(|| {
                        self.chain
                            .store
                            .native_payload(root.0)
                            .ok()
                            .flatten()
                            .map(|r| r.opening)
                    })
                },
            )
        } else {
            NativeIntent::from_claims(
                &context,
                self.context.epoch_anchor,
                operation,
                inputs,
                outputs,
            )
        }
        .map_err(|e| e.to_string())?;
        Ok(WalletNativeIntent::Operation(intent))
    }
    fn finish(
        &self,
        operation: NativeOperation,
        mut inputs: Vec<NativeInputClaim>,
        native: Vec<NativeOpening>,
        payments: Vec<(Address, u64)>,
        funding: Funding,
        extra: Vec<NativeOpening>,
    ) -> Result<WalletNativeIntent> {
        inputs.extend(funding.inputs);
        let count = native.len() + payments.len() + usize::from(funding.change.is_some());
        let slots = self.slots(count)?;
        let mut next = slots.into_iter();
        let mut outputs = Vec::new();
        for opening in native {
            outputs.push(NativeOutputClaim {
                output: TxOutput {
                    slot_index: next.next().unwrap(),
                    amount: opening.amount_micronoid(),
                    owner: opening.root(),
                },
                opening: Some(opening),
            });
        }
        for (owner, amount) in payments {
            outputs.push(NativeOutputClaim {
                output: TxOutput {
                    slot_index: next.next().unwrap(),
                    amount,
                    owner,
                },
                opening: None,
            });
        }
        if let Some(amount) = funding.change {
            outputs.push(NativeOutputClaim {
                output: TxOutput {
                    slot_index: next.next().unwrap(),
                    amount,
                    owner: self.context.owner,
                },
                opening: None,
            });
        }
        self.operation(operation, inputs, outputs, funding.fee, extra)
    }
    fn listing(
        &self,
        collection: CollectionId,
        serial: u64,
    ) -> Result<(ListingDefinition, NativeInputClaim)> {
        let opening = self.opening(NativeAssetLookup::Nft { collection, serial })?;
        let NativeOpening::NftMarket(NftMarketOpening::Listing(state)) = opening else {
            return Err("NFT is not currently listed".into());
        };
        let def = self
            .chain
            .store
            .native_payload(state.listing.0)
            .map_err(|e| e.to_string())?
            .ok_or("NFT listing terms unavailable")?
            .opening;
        let NativeOpening::NftMarket(NftMarketOpening::Definition(definition)) = def else {
            return Err("invalid NFT listing terms".into());
        };
        Ok((definition, self.claim(opening)?))
    }
}

pub(super) fn prepare(
    chain: &MdbxChainContext,
    key_index: u32,
    owner: Address,
    request: NativeWalletRequest,
    utxos: Vec<WalletUtxoInfo>,
    reserved: HashSet<u32>,
    floor: u64,
    budget: BlockSelectionBudget,
) -> Result<Prepared> {
    prepare_with_projection(
        chain, key_index, owner, request, utxos, reserved, floor, budget, None,
    )
}

pub(super) fn prepare_with_projection(
    chain: &MdbxChainContext,
    key_index: u32,
    owner: Address,
    request: NativeWalletRequest,
    utxos: Vec<WalletUtxoInfo>,
    reserved: HashSet<u32>,
    floor: u64,
    mut budget: BlockSelectionBudget,
    project: Option<&dyn Fn(&TradeIntent) -> Result<noid_miner::template::TradeProjection>>,
) -> Result<Prepared> {
    let encoded = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
    let seed = u64::from_le_bytes(blake3::hash(&encoded).as_bytes()[..8].try_into().unwrap())
        ^ u64::from_le_bytes(chain.tip_header().state_root[..8].try_into().unwrap())
        ^ u64::from_le_bytes(owner.0[..8].try_into().unwrap());
    let context = WalletNativeContext {
        key_index,
        owner,
        parent: *chain.tip_header(),
        epoch_anchor: next_user_epoch_anchor(chain)?,
    };
    context.candidate_height()?;
    let mut cash: Vec<_> = utxos
        .into_iter()
        .filter(|u| u.key_index == key_index && !u.reserved && !reserved.contains(&u.slot_index))
        .map(|u| NativeInputClaim {
            input: TxInput {
                slot_index: u.slot_index,
                amount: u.value_micronoid,
                creation_id: u.creation_id,
            },
            root: owner,
            opening: None,
        })
        .collect();
    cash.sort_by_key(|i| (std::cmp::Reverse(i.input.amount), i.input.slot_index));
    let planner = Planner {
        chain,
        context: context.clone(),
        reserved,
        cash,
        floor,
        seed,
    };
    let mut review = NativeWalletPreview {
        plan_id: String::new(),
        txid: String::new(),
        owner: owner.to_bech32(),
        key_index,
        height: planner.height(),
        parent_hash: hex::encode(noid_chain::block_id(chain.tip_header())),
        state_root: hex::encode(chain.tip_header().state_root),
        request: request.clone(),
        fee_micronoid: String::new(),
        fee_limit_micronoid: None,
        noid_debit_micronoid: "0".into(),
        noid_credit_micronoid: "0".into(),
        reserve_deposit_micronoid: None,
        initial_buy_cost_micronoid: None,
        redemption_micronoid: None,
        quoted_output: None,
        minimum_output: None,
        valid_until: None,
        asset_id: None,
        collection_id: None,
        serial: None,
        last_serial: None,
        input_count: 0,
        output_count: 0,
        pending_quote: None,
    };
    let intent = match &request {
        NativeWalletRequest::TransferToken {
            asset_id, units, ..
        }
        | NativeWalletRequest::BurnToken { asset_id, units } => {
            let asset = AssetId(hash(asset_id)?);
            review.asset_id = Some(hex::encode(asset.0));
            let units = integer(units, false)?;
            let (mut inputs, change) = planner.tokens(asset, units)?;
            let mut outputs = Vec::new();
            let mut credit = 0;
            let operation = if let NativeWalletRequest::TransferToken { recipient, .. } = &request {
                outputs.push(NativeOpening::TokenBalance(TokenBalance {
                    asset,
                    owner: Address::parse(recipient).map_err(|e| e.to_string())?,
                    units,
                    unlock_height: 0,
                }));
                NativeOperation::TransferToken { asset }
            } else {
                let opening = planner.opening(NativeAssetLookup::TokenReserve(asset))?;
                let NativeOpening::TokenReserve(reserve) = opening else {
                    return Err("invalid token reserve".into());
                };
                let (next, payout) = reserve.redeem(units).map_err(|e| e.to_string())?;
                inputs.push(planner.claim(opening)?);
                outputs.push(NativeOpening::TokenReserve(next));
                credit = payout;
                review.redemption_micronoid = Some(payout.to_string());
                NativeOperation::RedeemToken { asset }
            };
            if change != 0 {
                outputs.push(NativeOpening::TokenBalance(TokenBalance {
                    asset,
                    owner,
                    units: change,
                    unlock_height: 0,
                }));
            }
            let funding = planner.funding(inputs.len(), outputs.len(), 0, credit, false)?;
            planner.finish(operation, inputs, outputs, Vec::new(), funding, Vec::new())?
        }
        NativeWalletRequest::CreateToken {
            whole_tokens,
            metadata_hash,
            initial_buy_units,
        } => {
            let supply = launch_supply_from_whole(integer(whole_tokens, false)?)
                .map_err(|e| e.to_string())?;
            let deposit = noid_tx::asset_backing::TokenDenomination::new(TOKEN_DECIMALS)
                .and_then(|d| d.minimum_backing(supply))
                .map_err(|e| format!("token backing: {e:?}"))?;
            let purchased = initial_buy_units
                .as_deref()
                .map(|v| integer(v, true))
                .transpose()?
                .unwrap_or(0);
            let purchase_cost =
                launch::curve_cash_for_supply(supply, purchased).map_err(|e| e.to_string())?;
            let debit = deposit
                .checked_add(purchase_cost)
                .ok_or("launch funding overflow")?;
            let funding = planner.funding(0, 3 + usize::from(purchased != 0), debit, 0, true)?;
            let anchor = GenesisAnchor {
                chain: noid_chain::state::native_assets::native_chain_id(),
                owner,
                input: funding
                    .inputs
                    .first()
                    .ok_or("launch requires NOID funding")?
                    .input,
            };
            let token = FungibleDefinition::from_genesis(
                &anchor,
                supply,
                IssuanceRoute::Launchpad,
                hash(metadata_hash)?,
            )
            .map_err(|e| e.to_string())?;
            let definition =
                LaunchDefinition::from_genesis(&anchor, token).map_err(|e| e.to_string())?;
            let auxiliary = NativeOpening::Launch(LaunchOpening::Definition(definition));
            let definition_root = auxiliary.root();
            let state = definition
                .after_initial_purchase(purchased)
                .map_err(|e| e.to_string())?;
            let reserve =
                TokenReserve::from_definition(&token, deposit).map_err(|e| e.to_string())?;
            review.asset_id = Some(hex::encode(token.asset.0));
            review.reserve_deposit_micronoid = Some(deposit.to_string());
            review.initial_buy_cost_micronoid = Some(purchase_cost.to_string());
            let mut auxiliary = vec![auxiliary];
            let control = match state {
                launch::sequential::TradeState::Curve(state) => {
                    NativeOpening::Launch(LaunchOpening::State(state))
                }
                launch::sequential::TradeState::Market(pool) => {
                    auxiliary.push(NativeOpening::Market(market::MarketOpening::Definition(
                        definition.market_definition(),
                    )));
                    NativeOpening::Market(market::MarketOpening::Pool(pool))
                }
            };
            let mut outputs = vec![
                NativeOpening::FungibleDefinition(token),
                NativeOpening::TokenReserve(reserve),
                control,
            ];
            if purchased != 0 {
                outputs.push(NativeOpening::TokenBalance(TokenBalance {
                    asset: token.asset,
                    owner,
                    units: purchased,
                    unlock_height: 0,
                }));
                review.quoted_output = Some(purchased.to_string());
            }
            planner.finish(
                NativeOperation::Financial(FinancialOperation::CreateLaunch {
                    funding_input: 0,
                    definition: definition_root,
                }),
                Vec::new(),
                outputs,
                Vec::new(),
                funding,
                auxiliary,
            )?
        }
        NativeWalletRequest::CreateCollection {
            maximum_items,
            metadata_hash,
        } => {
            let funding = planner.funding(0, 1, 0, 0, false)?;
            let anchor = GenesisAnchor {
                chain: noid_chain::state::native_assets::native_chain_id(),
                owner,
                input: funding
                    .inputs
                    .first()
                    .ok_or("collection requires NOID funding")?
                    .input,
            };
            let collection = NftCollection::from_genesis(
                &anchor,
                integer(maximum_items, false)?,
                hash(metadata_hash)?,
            )
            .map_err(|e| e.to_string())?;
            review.collection_id = Some(hex::encode(collection.collection.0));
            planner.finish(
                NativeOperation::CreateCollection { funding_input: 0 },
                Vec::new(),
                vec![NativeOpening::NftCollection(collection)],
                Vec::new(),
                funding,
                Vec::new(),
            )?
        }
        NativeWalletRequest::MintNft { collection_id, .. }
        | NativeWalletRequest::MintNfts { collection_id, .. } => {
            let metadata: Vec<_> = match &request {
                NativeWalletRequest::MintNft { metadata_hash, .. } => vec![metadata_hash],
                NativeWalletRequest::MintNfts {
                    metadata_hashes, ..
                } => metadata_hashes.iter().collect(),
                _ => unreachable!(),
            };
            if metadata.is_empty()
                || metadata.len() > noid_tx::MAX_PAGED_SPEND_OUTPUTS.saturating_sub(2)
            {
                return Err("choose a nonempty NFT batch within the output limit".into());
            }
            let metadata = metadata
                .into_iter()
                .map(|value| hash(value))
                .collect::<Result<Vec<_>>>()?;
            let collection = CollectionId(hash(collection_id)?);
            let opening = planner.opening(NativeAssetLookup::Collection(collection))?;
            let NativeOpening::NftCollection(mut next) = opening else {
                return Err("invalid NFT collection".into());
            };
            if next.creator != owner {
                return Err("active address does not own this collection".into());
            }
            let first_serial = next
                .issued_items
                .checked_add(1)
                .ok_or("NFT serial exhausted")?;
            next.issued_items = next
                .issued_items
                .checked_add(metadata.len() as u64)
                .ok_or("NFT serial exhausted")?;
            if next.issued_items > next.maximum_items {
                return Err("NFT collection supply is exhausted".into());
            }
            review.collection_id = Some(collection_id.clone());
            review.serial = Some(first_serial.to_string());
            if matches!(request, NativeWalletRequest::MintNfts { .. }) {
                review.last_serial = Some(next.issued_items.to_string());
            }
            let mut outputs = vec![NativeOpening::NftCollection(next)];
            outputs.extend(metadata.into_iter().enumerate().map(|(index, metadata)| {
                NativeOpening::NftItem(NftItem {
                    collection,
                    owner,
                    serial: first_serial + index as u64,
                    metadata,
                    unlock_height: 0,
                })
            }));
            let inputs = vec![planner.claim(opening)?];
            let funding = planner.funding(1, outputs.len(), 0, 0, false)?;
            planner.finish(
                NativeOperation::MintNft,
                inputs,
                outputs,
                Vec::new(),
                funding,
                Vec::new(),
            )?
        }
        NativeWalletRequest::TransferNft {
            collection_id,
            serial,
            ..
        }
        | NativeWalletRequest::BurnNft {
            collection_id,
            serial,
        }
        | NativeWalletRequest::ListNft {
            collection_id,
            serial,
            ..
        } => {
            let collection = CollectionId(hash(collection_id)?);
            let serial = integer(serial, false)?;
            let opening = planner.opening(NativeAssetLookup::Nft { collection, serial })?;
            let NativeOpening::NftItem(item) = opening else {
                return Err("NFT is currently listed".into());
            };
            if item.owner != owner {
                return Err("active address does not own this NFT".into());
            }
            let input = planner.claim(opening)?;
            review.collection_id = Some(hex::encode(collection.0));
            review.serial = Some(serial.to_string());
            match &request {
                NativeWalletRequest::TransferNft { recipient, .. } => {
                    let next = NftItem {
                        owner: Address::parse(recipient).map_err(|e| e.to_string())?,
                        ..item
                    };
                    let funding = planner.funding(1, 1, 0, 0, false)?;
                    planner.finish(
                        NativeOperation::TransferNft,
                        vec![input],
                        vec![NativeOpening::NftItem(next)],
                        Vec::new(),
                        funding,
                        Vec::new(),
                    )?
                }
                NativeWalletRequest::BurnNft { .. } => {
                    let funding = planner.funding(1, 0, 0, 0, false)?;
                    planner.finish(
                        NativeOperation::BurnNft,
                        vec![input],
                        Vec::new(),
                        Vec::new(),
                        funding,
                        Vec::new(),
                    )?
                }
                NativeWalletRequest::ListNft {
                    ask_micronoid,
                    expiry_height,
                    ..
                } => {
                    let definition = ListingDefinition::from_item(
                        item,
                        input.input.creation_id,
                        integer(ask_micronoid, false)?,
                        *expiry_height,
                        planner.height(),
                    )
                    .map_err(|e| e.to_string())?;
                    let auxiliary =
                        NativeOpening::NftMarket(NftMarketOpening::Definition(definition));
                    let state = ListingState::initial(definition).map_err(|e| e.to_string())?;
                    let funding = planner.funding(1, 1, NFT_FEE_CREDIT, 0, true)?;
                    planner.finish(
                        NativeOperation::Financial(FinancialOperation::CreateListing {
                            definition: auxiliary.root(),
                        }),
                        vec![input],
                        vec![NativeOpening::NftMarket(NftMarketOpening::Listing(state))],
                        Vec::new(),
                        funding,
                        vec![auxiliary],
                    )?
                }
                _ => unreachable!(),
            }
        }
        NativeWalletRequest::BuyNft {
            collection_id,
            serial,
            maximum_ask_micronoid,
        } => {
            let collection = CollectionId(hash(collection_id)?);
            let serial = integer(serial, false)?;
            let (definition, input) = planner.listing(collection, serial)?;
            if definition.ask > integer(maximum_ask_micronoid, false)? {
                return Err("NFT asking price exceeds the approved maximum".into());
            }
            let funding = planner.funding(1, 2, definition.ask, 0, true)?;
            let slots = planner.slots(2 + usize::from(funding.change.is_some()))?;
            let mut inputs = vec![input];
            inputs.extend(funding.inputs);
            let item = NativeOpening::NftItem(definition.item(owner).map_err(|e| e.to_string())?);
            let mut outputs = vec![
                NativeOutputClaim {
                    output: TxOutput {
                        slot_index: slots[0],
                        owner: definition.seller,
                        amount: definition
                            .ask
                            .checked_add(NFT_FEE_CREDIT)
                            .ok_or("NFT payment overflow")?,
                    },
                    opening: None,
                },
                NativeOutputClaim {
                    output: TxOutput {
                        slot_index: slots[1],
                        owner: item.root(),
                        amount: item.amount_micronoid(),
                    },
                    opening: Some(item),
                },
            ];
            if let Some(amount) = funding.change {
                outputs.push(NativeOutputClaim {
                    output: TxOutput {
                        slot_index: slots[2],
                        owner,
                        amount,
                    },
                    opening: None,
                });
            }
            planner.operation(
                NativeOperation::Financial(FinancialOperation::Purchase {
                    parent: NativeParentRef {
                        slot_index: input.input.slot_index,
                        creation_id: input.input.creation_id,
                        root: input.root,
                    },
                }),
                inputs,
                outputs,
                funding.fee,
                Vec::new(),
            )?
        }
        NativeWalletRequest::CancelListing {
            collection_id,
            serial,
        } => {
            let collection = CollectionId(hash(collection_id)?);
            let serial = integer(serial, false)?;
            let (definition, input) = planner.listing(collection, serial)?;
            if definition.seller != owner {
                return Err("active address does not own this listing".into());
            }
            let fee = planner.fee(1, 2, true)?;
            let refund = NFT_FEE_CREDIT
                .checked_sub(fee)
                .filter(|a| *a > 0)
                .ok_or("NFT listing fee credit is insufficient")?;
            planner.finish(
                NativeOperation::Financial(FinancialOperation::CancelListing),
                vec![input],
                vec![NativeOpening::NftItem(
                    definition.item(owner).map_err(|e| e.to_string())?,
                )],
                vec![(owner, refund)],
                Funding {
                    inputs: Vec::new(),
                    fee,
                    change: None,
                },
                Vec::new(),
            )?
        }
        NativeWalletRequest::Trade {
            asset_id,
            buy,
            gross_input,
            minimum_output,
            slippage_bps,
            valid_until,
        } => {
            let asset = AssetId(hash(asset_id)?);
            let gross = integer(gross_input, false)?;
            let (mut inputs, _) = if *buy {
                (Vec::new(), 0)
            } else {
                planner.tokens(asset, gross)?
            };
            let principal = if *buy { u128::from(gross) } else { 0 };
            let mut total = 0u128;
            let mut fee_limit = 0;
            for cash in &planner.cash {
                inputs.push(*cash);
                total += u128::from(cash.input.amount);
                fee_limit = planner.fee(inputs.len() + 1, 4, false)?;
                if total >= principal + u128::from(fee_limit) {
                    break;
                }
            }
            if total < principal + u128::from(fee_limit) || fee_limit == 0 {
                return Err("insufficient NOID for trade funding and fee limit".into());
            }
            inputs.sort_by_key(|i| i.input.slot_index);
            let until = valid_until.unwrap_or(planner.height().saturating_add(3));
            if until < planner.height() || until > planner.height().saturating_add(30) {
                return Err("trade expiry must be within30 blocks".into());
            }
            let mut trade = TradeIntent {
                policy: TradePolicy {
                    chain: noid_chain::state::native_assets::native_chain_id(),
                    epoch_anchor: context.epoch_anchor,
                    owner,
                    asset,
                    recipient: owner,
                    side: if *buy {
                        LaunchSide::Buy
                    } else {
                        LaunchSide::Sell
                    },
                    gross_input: gross,
                    minimum_output: 1,
                    fee_limit,
                    valid_from: planner.height(),
                    valid_until: until,
                },
                funding: inputs,
            };
            let parent = chain
                .store
                .native_trade_parent_at(
                    asset,
                    context.parent.height,
                    noid_chain::block_id(&context.parent),
                )
                .map_err(|e| e.to_string())?
                .ok_or("native market is unavailable")?;
            let boundary = TradeBoundary {
                chain: trade.policy.chain,
                epoch_anchor: context.epoch_anchor,
                parent_id: noid_chain::block_id(&context.parent),
                height: planner.height(),
            };
            let confirmed =
                SequencingPlan::execute(parent.market, boundary, std::slice::from_ref(&trade))
                    .map_err(|e| e.to_string())?
                    .fills()
                    .first()
                    .map(|fill| fill.outcome);
            let bps = slippage_bps.unwrap_or(100);
            if bps >= 10_000 {
                return Err("trade slippage must be below10000 basis points".into());
            }
            if let Some(minimum) = minimum_output {
                trade.policy.minimum_output = integer(minimum, false)?;
            }
            let initial = project.map(|project| project(&trade)).transpose()?;
            let initial_outcome = initial
                .as_ref()
                .and_then(|p| p.outcome)
                .or(confirmed)
                .ok_or("trade has no executable fill")?;
            if minimum_output.is_none() {
                trade.policy.minimum_output = u64::try_from(
                    (u128::from(initial_outcome.output) * u128::from(10_000 - bps))
                        .div_ceil(10_000),
                )
                .unwrap()
                .max(1);
            }
            let pending = if minimum_output.is_none() {
                project.map(|project| project(&trade)).transpose()?
            } else {
                initial
            };
            let outcome = pending
                .as_ref()
                .and_then(|p| p.outcome)
                .or(confirmed)
                .ok_or("trade has no executable fill")?;
            if trade.policy.minimum_output > outcome.output {
                return Err("trade quotation is below the approved minimum".into());
            }
            let charge = noid_chain::state::native_assets::trade::quote_trade_charge(
                &trade,
                boundary,
                outcome,
                noid_chain::state::native_assets::market::liquidity::MarketFeeContext::from_state(
                    &chain.state,
                ),
            )
            .map_err(|e| e.to_string())?;
            review.fee_micronoid = charge.fee.to_string();
            noid_effect(
                &mut review,
                u128::from(charge.fee)
                    + if *buy {
                        u128::from(outcome.spent_input)
                    } else {
                        0
                    },
                if *buy { 0 } else { u128::from(outcome.output) },
            );
            review.fee_limit_micronoid = Some(fee_limit.to_string());
            review.quoted_output = Some(outcome.output.to_string());
            review.pending_quote = pending.map(|p| NativePendingQuote {
                pending_policies: p.pending_policies,
                selected_policies: p.selected_policies,
                selected_markets: p.selected_markets,
                position: p.position,
                output: p.outcome.map(|o| o.output.to_string()),
                spent_input: p.outcome.map(|o| o.spent_input.to_string()),
                market_fee: p.outcome.map(|o| o.market_fee.to_string()),
                network_fee: p.fee.map(|fee| fee.to_string()),
                confirmed_output: confirmed.map(|o| o.output.to_string()),
            });
            review.minimum_output = Some(trade.policy.minimum_output.to_string());
            review.valid_until = Some(until);
            review.asset_id = Some(asset_id.clone());
            WalletNativeIntent::Trade(trade)
        }
    };
    let proof = WalletNativeProofRequest { context, intent };
    let claims = proof.checked_claims()?;
    review.txid = hex::encode(claims.txid);
    review.input_count = claims.inputs.len();
    review.output_count = claims.output_slots.len();
    let bytes = match &proof.intent {
        WalletNativeIntent::Operation(intent) => {
            let spent = claims
                .inputs
                .iter()
                .filter(|i| i.opening.is_none())
                .map(|i| u128::from(i.input.amount))
                .sum();
            let received = intent
                .pages
                .iter()
                .skip(1)
                .flat_map(|page| page.body.live_outputs().map(|(_, output)| output))
                .zip(&intent.output_openings)
                .filter(|(output, opening)| opening.is_none() && output.owner == owner)
                .map(|(output, _)| u128::from(output.amount))
                .sum();
            noid_effect(&mut review, spent, received);
            let usage = NativeResourceUsage::for_intent(intent).map_err(|e| e.to_string())?;
            if !budget.try_consume(intent.pages.len(), claims.inputs.len(), 0, usage) {
                return Err("native operation exceeds the active block profile".into());
            }
            review.fee_micronoid = intent
                .validate_structure()
                .map_err(|e| e.to_string())?
                .fee
                .to_string();
            intent.to_bytes().map_err(|e| e.to_string())?
        }
        WalletNativeIntent::Trade(intent) => {
            let (pages, usage) = trade_policy_resources(intent).map_err(|e| e.to_string())?;
            if !budget.try_consume(pages, claims.inputs.len(), 0, usage) {
                return Err("trade exceeds the active block profile".into());
            }
            intent.to_bytes().map_err(|e| e.to_string())?
        }
    };
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"NOIDWalletNativePlan21");
    hasher.update(&proof.context.parent.to_bytes());
    hasher.update(&proof.context.key_index.to_le_bytes());
    hasher.update(&proof.context.owner.0);
    hasher.update(&proof.context.epoch_anchor);
    hasher.update(&encoded);
    hasher.update(&bytes);
    review.plan_id = hasher.finalize().to_hex().to_string();
    Ok(Prepared { proof, review })
}

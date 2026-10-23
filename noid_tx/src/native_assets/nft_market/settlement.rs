// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Atomic item delivery, fixed seller payment and beneficiary refunds.

use super::{queue::ListingBatch, *};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NftPayout {
    pub owner: Address,
    pub noid: u64,
    pub item: Option<NftItem>,
}
impl NftPayout {
    pub fn opening(self) -> Option<NativeOpening> {
        self.item.map(NativeOpening::NftItem)
    }
    pub fn root(self) -> Address {
        self.opening().map(|o| o.root()).unwrap_or(self.owner)
    }
}
fn payouts(cash: BTreeMap<Digest, u64>, item: Option<NftItem>) -> Vec<NftPayout> {
    let mut out: Vec<_> = cash
        .into_iter()
        .filter(|(_, n)| *n != 0)
        .map(|(owner, noid)| NftPayout {
            owner: Address(owner),
            noid,
            item: None,
        })
        .collect();
    if let Some(item) = item {
        out.push(NftPayout {
            owner: item.owner,
            noid: 0,
            item: Some(item),
        });
    }
    out
}
fn add(
    cash: &mut BTreeMap<Digest, u64>,
    owner: Address,
    amount: u64,
) -> Result<(), NftMarketError> {
    let v = cash.entry(owner.0).or_default();
    *v = v.checked_add(amount).ok_or(NftMarketError::Capacity)?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListingSettlement {
    winner: Digest,
    fee: u64,
    payouts: Vec<NftPayout>,
}
impl ListingSettlement {
    pub fn calculate(batch: &ListingBatch, height: u64, fee: u64) -> Result<Self, NftMarketError> {
        batch.settlement_allowed(height)?;
        let count = batch.requests().len() as u64;
        if fee > count * NFT_MAX_SETTLEMENT_FEE_PER_REQUEST {
            return Err(NftMarketError::Fee);
        }
        let (winner_index, winner) = batch
            .requests()
            .iter()
            .enumerate()
            .min_by_key(|(_, r)| {
                let root = r.request.root();
                (
                    r.request.payer_priority(),
                    root.0,
                    super::super::market::queue::funded_request_key(
                        root,
                        r.slot_index,
                        r.creation_id,
                    ),
                )
            })
            .ok_or(NftMarketError::Capacity)?;
        let winner_key = winner.key();
        let d = batch.definition();
        let mut cash = BTreeMap::new();
        add(&mut cash, d.seller, d.ask + NFT_FEE_CREDIT)?;
        let mut incoming = u128::from(NFT_FEE_CREDIT);
        for (i, r) in batch.requests().iter().enumerate() {
            let spent = if i == winner_index { d.ask } else { 0 };
            let charged = fee / count + u64::from((i as u64) < fee % count);
            let refund = r
                .request
                .budget
                .checked_sub(spent)
                .and_then(|v| v.checked_add(NFT_FEE_CREDIT - charged))
                .ok_or(NftMarketError::Conservation)?;
            add(&mut cash, r.request.payer, refund)?;
            incoming += u128::from(r.request.noid_value()?);
        }
        let out = payouts(cash, Some(d.item(winner.request.recipient)?));
        if out.iter().map(|p| u128::from(p.noid)).sum::<u128>() + u128::from(fee) != incoming {
            return Err(NftMarketError::Conservation);
        }
        Ok(Self {
            winner: winner_key,
            fee,
            payouts: out,
        })
    }
    pub fn winner(&self) -> Digest {
        self.winner
    }
    pub fn fee(&self) -> u64 {
        self.fee
    }
    pub fn payouts(&self) -> &[NftPayout] {
        &self.payouts
    }
}

pub fn purchase_refund(
    r: PurchaseRequest,
    height: u64,
    fee: u64,
) -> Result<NftPayout, NftMarketError> {
    r.validate()?;
    if height < timeout_height(r.registered_height)? {
        return Err(NftMarketError::Phase);
    }
    if fee >= NFT_FEE_CREDIT {
        return Err(NftMarketError::Fee);
    }
    Ok(NftPayout {
        owner: r.payer,
        noid: r.noid_value()? - fee,
        item: None,
    })
}
pub fn offer_refund(o: NftOffer, fee: u64) -> Result<NftPayout, NftMarketError> {
    o.validate()?;
    if fee >= NFT_FEE_CREDIT {
        return Err(NftMarketError::Fee);
    }
    Ok(NftPayout {
        owner: o.payer,
        noid: o.noid_value()? - fee,
        item: None,
    })
}
pub fn offer_acceptance(
    o: NftOffer,
    item: NftItem,
    height: u64,
    fee: u64,
) -> Result<Vec<NftPayout>, NftMarketError> {
    o.check_item(item, height)?;
    if fee >= NFT_FEE_CREDIT {
        return Err(NftMarketError::Fee);
    }
    let mut cash = BTreeMap::new();
    add(&mut cash, item.owner, o.price)?;
    add(&mut cash, o.payer, NFT_FEE_CREDIT - fee)?;
    let next = NftItem {
        owner: o.recipient,
        unlock_height: 0,
        ..item
    };
    Ok(payouts(cash, Some(next)))
}
pub fn listing_return(d: ListingDefinition, fee: u64) -> Result<Vec<NftPayout>, NftMarketError> {
    d.validate()?;
    if fee >= NFT_FEE_CREDIT {
        return Err(NftMarketError::Fee);
    }
    let mut cash = BTreeMap::new();
    add(&mut cash, d.seller, NFT_FEE_CREDIT - fee)?;
    Ok(payouts(cash, Some(d.item(d.seller)?)))
}

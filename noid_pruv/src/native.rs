// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Typed templates for the native wallet's preview and authorization workflow.

use noid_poseidon2b::primitives::Address;
use noid_tx::native_assets::{launch::launch_supply_from_whole, market::MARKET_QUANTITY_MAX};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{Error, MAX_SOURCE_BYTES};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct AssetId([u8; 32]);

impl AssetId {
    pub fn bytes(self) -> [u8; 32] {
        self.0
    }
}

impl TryFrom<String> for AssetId {
    type Error = Error;
    fn try_from(value: String) -> Result<Self, Error> {
        let bytes = hash(&value)?;
        if bytes == [0; 32] {
            return Err(Error::plain("asset and collection IDs must be nonzero"));
        }
        Ok(Self(bytes))
    }
}

impl From<AssetId> for String {
    fn from(value: AssetId) -> Self {
        value.0.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Quantity(u64);

impl Quantity {
    pub fn get(self) -> u64 {
        self.0
    }
}

impl TryFrom<String> for Quantity {
    type Error = Error;
    fn try_from(value: String) -> Result<Self, Error> {
        if value.is_empty()
            || value.starts_with('0')
            || !value.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(Error::plain(
                "amounts must be positive canonical decimal strings",
            ));
        }
        value
            .parse::<u64>()
            .map(Self)
            .map_err(|_| Error::plain("amount exceeds u64"))
    }
}

impl From<Quantity> for String {
    fn from(value: Quantity) -> Self {
        value.0.to_string()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Owner(Address);

impl Owner {
    pub fn address(self) -> Address {
        self.0
    }
}

impl TryFrom<String> for Owner {
    type Error = Error;
    fn try_from(value: String) -> Result<Self, Error> {
        let address = Address::parse(&value).map_err(|error| Error::plain(error.to_string()))?;
        if address == Address([0; 32]) || address.to_bech32() != value {
            return Err(Error::plain("use a canonical nonzero Parano1d address"));
        }
        Ok(Self(address))
    }
}

impl From<Owner> for String {
    fn from(value: Owner) -> Self {
        value.0.to_bech32()
    }
}

fn hash(value: &str) -> Result<[u8; 32], Error> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Error::plain(
            "use exactly 64 lowercase hexadecimal characters",
        ));
    }
    let mut bytes = [0; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let digit = |byte: u8| {
            if byte.is_ascii_digit() {
                byte - b'0'
            } else {
                byte - b'a' + 10
            }
        };
        bytes[index] = digit(pair[0]) * 16 + digit(pair[1]);
    }
    Ok(bytes)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum NativeTemplate {
    TransferToken {
        asset_id: AssetId,
        units: Quantity,
        recipient: Owner,
    },
    BurnToken {
        asset_id: AssetId,
        units: Quantity,
    },
    Trade {
        asset_id: AssetId,
        buy: bool,
        gross_input: Quantity,
        minimum_output: Quantity,
        #[serde(default)]
        slippage_bps: Option<u16>,
        valid_until: u64,
    },
    CreateToken {
        whole_tokens: Quantity,
        metadata_hash: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        initial_buy_units: Option<Quantity>,
    },
    CreateCollection {
        maximum_items: Quantity,
        metadata_hash: String,
    },
    MintNft {
        collection_id: AssetId,
        metadata_hash: String,
    },
    TransferNft {
        collection_id: AssetId,
        serial: Quantity,
        recipient: Owner,
    },
    BurnNft {
        collection_id: AssetId,
        serial: Quantity,
    },
    ListNft {
        collection_id: AssetId,
        serial: Quantity,
        ask_micronoid: Quantity,
        expiry_height: u64,
    },
    BuyNft {
        collection_id: AssetId,
        serial: Quantity,
        maximum_ask_micronoid: Quantity,
    },
    CancelListing {
        collection_id: AssetId,
        serial: Quantity,
    },
}

impl NativeTemplate {
    pub fn parse(source: &str) -> Result<Self, Error> {
        if source.len() > MAX_SOURCE_BYTES {
            return Err(Error::plain("native template exceeds 64 KiB"));
        }
        let template: Self =
            serde_json::from_str(source).map_err(|error| Error::plain(error.to_string()))?;
        template.validate()?;
        Ok(template)
    }

    pub fn validate(&self) -> Result<(), Error> {
        match self {
            Self::CreateToken {
                whole_tokens,
                metadata_hash,
                initial_buy_units,
            } => {
                let supply = launch_supply_from_whole(whole_tokens.get())
                    .map_err(|error| Error::plain(error.to_string()))?;
                noid_tx::native_assets::launch::curve_cash_for_supply(
                    supply,
                    initial_buy_units
                        .as_ref()
                        .map_or(0, |quantity| quantity.get()),
                )
                .map_err(|error| Error::plain(error.to_string()))?;
                hash(metadata_hash)?;
            }
            Self::CreateCollection { metadata_hash, .. } | Self::MintNft { metadata_hash, .. } => {
                hash(metadata_hash)?;
            }
            Self::Trade {
                gross_input,
                minimum_output,
                slippage_bps,
                valid_until,
                ..
            } => {
                if slippage_bps.is_some() {
                    return Err(Error::plain(
                        "native templates require an explicit minimum_output",
                    ));
                }
                if gross_input.get() > MARKET_QUANTITY_MAX
                    || minimum_output.get() > MARKET_QUANTITY_MAX
                    || *valid_until == 0
                {
                    return Err(Error::plain(
                        "trade amount or expiry exceeds the native bounds",
                    ));
                }
            }
            Self::ListNft {
                ask_micronoid,
                expiry_height,
                ..
            } => {
                let maximum =
                    MARKET_QUANTITY_MAX - 2 * noid_tx::native_assets::nft_market::NFT_FEE_CREDIT;
                if ask_micronoid.get() > maximum || *expiry_height == 0 {
                    return Err(Error::plain("NFT ask or expiry exceeds the native bounds"));
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// The action executed by the native relation after wallet preparation.
    pub fn operation_code(&self) -> u16 {
        match self {
            Self::TransferToken { .. } => 2,
            Self::BurnToken { .. } => 3,
            Self::Trade { .. } => 80,
            Self::CreateToken { .. } => 48,
            Self::CreateCollection { .. } => 5,
            Self::MintNft { .. } => 6,
            Self::TransferNft { .. } => 7,
            Self::BurnNft { .. } => 8,
            Self::ListNft { .. } => 64,
            Self::BuyNft { .. } => 65,
            Self::CancelListing { .. } => 66,
        }
    }

    pub fn request(&self) -> Result<Value, Error> {
        self.validate()?;
        serde_json::to_value(self).map_err(|error| Error::plain(error.to_string()))
    }

    pub fn preview_rpc(&self) -> Result<Value, Error> {
        Ok(
            json!({"jsonrpc":"2.0","id":1,"method":"paranoid_walletPreviewNative","params":[self.request()?]}),
        )
    }

    /// Preserve every declared term when authorizing a reviewed node plan.
    pub fn submit_rpc(&self, plan_id: &str) -> Result<Value, Error> {
        if hash(plan_id)? == [0; 32] {
            return Err(Error::plain(
                "use the plan_id returned by walletPreviewNative",
            ));
        }
        Ok(
            json!({"jsonrpc":"2.0","id":1,"method":"paranoid_walletSubmitNative","params":[self.request()?,plan_id]}),
        )
    }
}

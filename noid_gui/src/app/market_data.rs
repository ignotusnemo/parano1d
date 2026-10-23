// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use super::*;

impl App {
    pub(super) fn refresh_price_chart(&mut self) -> Task<Message> {
        if self.backend_state != BackendState::Online
            || self.shutting_down
            || self.section != Section::Tokens
            || self.assets.token_page != crate::assets::Page::Trade
        {
            self.assets.chart.deactivate();
            return Task::none();
        }
        if !self.assets.markets.complete {
            return Task::none();
        }
        let context = self
            .assets
            .live
            .selected_asset
            .and_then(|id| self.assets.markets.markets.get(&id))
            .filter(|market| market.phase == crate::assets::catalog::Phase::Dex)
            .zip(self.assets.markets.key.as_ref())
            .map(|(market, key)| {
                (
                    market.id,
                    key.clone(),
                    crate::market_data::Price {
                        noid: market.price_numerator,
                        tokens: market.price_denominator,
                    },
                )
            });
        let Some((asset, key, price)) = context else {
            self.assets.chart.deactivate();
            return Task::none();
        };
        let mut tasks = Vec::new();
        if let Some((generation, previous)) = self.assets.chart.begin_point(asset, &key, price) {
            let backend = self.backend.clone();
            let requested = key.clone();
            tasks.push(Task::perform(
                async move { backend.chart_point_is_canonical(previous).await },
                move |result| {
                    Message::ChartPointChecked(generation, asset, requested.clone(), price, result)
                },
            ));
        }
        if let Some(generation) = self.assets.chart.begin(self.media_downloads, &key) {
            let backend = self.backend.clone();
            tasks.push(Task::perform(
                async move { backend.external_price_history(asset, key).await },
                move |result| Message::ExternalPriceHistory(generation, asset, result),
            ));
        }
        Task::batch(tasks)
    }
}

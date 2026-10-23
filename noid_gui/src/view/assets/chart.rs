// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use super::*;
use crate::assets::catalog::Market;
use crate::assets::chart::Point as LivePoint;
use crate::market_data::Block;
use iced::widget::column;
use noid_tx::native_assets::launch::LaunchDefinition;

pub(super) fn view<'a>(app: &'a App, market: &'a Market) -> El<'a> {
    let spot = market.price_numerator as f64 / market.price_denominator as f64;
    let curve = market.curve;
    let mut body = Column::new().spacing(10);
    if let Some(definition) = curve {
        let start = definition.marginal_price(0).ok();
        let end = definition.marginal_price(definition.sale_units()).ok();
        if let (Some(start), Some(end)) = (start, end) {
            body = body.push(row![
                column![
                    label("START / NOID"),
                    value(format!(
                        "{:.8}",
                        start.numerator as f64 / start.denominator as f64
                    ))
                ]
                .spacing(4),
                space(),
                column![
                    label("AT DEX / NOID"),
                    value(format!(
                        "{:.8}",
                        end.numerator as f64 / end.denominator as f64
                    ))
                ]
                .spacing(4),
            ]);
        }
        body = body
            .push(
                canvas(Plot::Curve(definition, market.sold_units))
                    .width(Length::Fill)
                    .height(248),
            )
            .push(row![
                label(&format!(
                    "SOLD {} / {}",
                    crate::assets::live::units(market.sold_units.into()),
                    crate::assets::live::units(market.sale_units.into())
                )),
                space(),
                text(format!(
                    "{:.3}%",
                    market.sold_units as f64 / market.sale_units as f64 * 100.0
                ))
                .size(12)
                .color(GREEN),
            ])
            .push(hint(
                "Price by tokens sold. The current point moves with confirmed buys and sells.",
            ));
    } else {
        let state = &app.assets.chart;
        let through = app.assets.markets.key.as_ref().map_or(0, |key| key.height);
        let from = through.saturating_sub(state.span.saturating_sub(1));
        let blocks = state
            .history
            .as_ref()
            .filter(|h| h.asset == hex::encode(market.id))
            .map(|h| {
                h.blocks
                    .iter()
                    .filter(|b| b.header.height >= from && b.header.height <= through)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        let points = if state.asset == Some(market.id) {
            state
                .points
                .iter()
                .filter(|p| p.height >= from && p.height <= through)
                .cloned()
                .collect()
        } else {
            Vec::new()
        };
        let ranges = row![
            control("120 BLOCKS", Action::ChartSpan(120), state.span == 120),
            control("480 BLOCKS", Action::ChartSpan(480), state.span == 480),
        ]
        .spacing(6);
        body = body
            .push(row![label("NOID / TOKEN"), space(), ranges].align_y(Alignment::Center))
            .push(
                canvas(Plot::Market {
                    blocks,
                    points,
                    spot,
                    through,
                    span: state.span,
                })
                .width(Length::Fill)
                .height(248),
            )
            .push(hint(if !app.media_downloads {
                "Live from opening · External data is off"
            } else if state.loading {
                "Loading price history · Live prices from your node"
            } else if state.error.is_some() {
                "History temporarily unavailable · Live prices from your node"
            } else {
                "Trade history · Current price from your node"
            }))
            .push(line())
            .push(pair(
                "POOL / NOID",
                crate::model::format_micronoid(market.noid),
            ))
            .push(pair(
                "POOL / TOKENS",
                crate::assets::live::units(market.inventory.into()),
            ));
    }
    panel(
        if curve.is_some() {
            "BONDING CURVE"
        } else {
            "DEX PRICE"
        },
        CYAN,
        text(format!("SPOT {spot:.8} NOID"))
            .size(12)
            .color(GREEN)
            .into(),
        body.into(),
        true,
    )
    .into()
}

enum Plot {
    Curve(LaunchDefinition, u64),
    Market {
        blocks: Vec<Block>,
        points: Vec<LivePoint>,
        spot: f64,
        through: u64,
        span: u64,
    },
}

fn caption(frame: &mut canvas::Frame, content: impl Into<String>, x: f32, y: f32, color: Color) {
    frame.fill_text(canvas::Text {
        content: content.into(),
        position: Point::new(x, y),
        size: 10.into(),
        color,
        font: theme::TECH_FONT,
        ..Default::default()
    });
}

fn stroke(frame: &mut canvas::Frame, a: Point, b: Point, color: Color, width: f32) {
    frame.stroke(
        &canvas::Path::line(a, b),
        canvas::Stroke::default()
            .with_color(color)
            .with_width(width),
    );
}

impl canvas::Program<Message> for Plot {
    type State = ();

    fn update(
        &self,
        _: &mut (),
        event: &canvas::Event,
        _: Rectangle,
        _: iced::mouse::Cursor,
    ) -> Option<canvas::Action<Message>> {
        matches!(
            event,
            canvas::Event::Mouse(
                iced::mouse::Event::CursorMoved { .. } | iced::mouse::Event::CursorLeft
            )
        )
        .then(canvas::Action::request_redraw)
    }

    fn mouse_interaction(
        &self,
        _: &(),
        bounds: Rectangle,
        cursor: iced::mouse::Cursor,
    ) -> iced::mouse::Interaction {
        if cursor.is_over(bounds) {
            iced::mouse::Interaction::Crosshair
        } else {
            iced::mouse::Interaction::default()
        }
    }

    fn draw(
        &self,
        _: &(),
        renderer: &Renderer,
        _: &Theme,
        bounds: Rectangle,
        cursor: iced::mouse::Cursor,
    ) -> Vec<canvas::Geometry> {
        let mut f = canvas::Frame::new(renderer, bounds.size());
        let (left, right, top, bottom) = (
            12.,
            (bounds.width - 94.).max(24.),
            26.,
            (bounds.height - 35.).max(40.),
        );
        f.fill_rectangle(
            Point::ORIGIN,
            bounds.size(),
            Color::from_rgba8(10, 14, 23, 0.60),
        );
        let (min, max) = match self {
            Self::Curve(definition, _) => {
                let a = definition.marginal_price(0).ok();
                let b = definition.marginal_price(definition.sale_units()).ok();
                let (Some(a), Some(b)) = (a, b) else {
                    return vec![f.into_geometry()];
                };
                (
                    a.numerator as f64 / a.denominator as f64 * 0.90,
                    b.numerator as f64 / b.denominator as f64 * 1.08,
                )
            }
            Self::Market {
                blocks,
                points,
                spot,
                ..
            } => {
                let mut min = *spot;
                let mut max = *spot;
                for candle in blocks.iter().filter_map(|b| b.candle.as_ref()) {
                    min = min.min(candle.low.value());
                    max = max.max(candle.high.value());
                }
                for point in points {
                    min = min.min(point.price.value());
                    max = max.max(point.price.value());
                }
                let pad = ((max - min) * 0.12).max(max * 0.003).max(f64::MIN_POSITIVE);
                ((min - pad).max(0.0), max + pad)
            }
        };
        let y = |value: f64| bottom - ((value - min) / (max - min)) as f32 * (bottom - top);
        for i in 0..5 {
            let py = top + (bottom - top) * i as f32 / 4.;
            stroke(
                &mut f,
                Point::new(left, py),
                Point::new(right, py),
                LINE,
                0.7,
            );
            let price = max - (max - min) * i as f64 / 4.;
            caption(&mut f, format!("{price:.8}"), right + 9., py - 6., DIM);
        }
        for i in 0..5 {
            let px = left + (right - left) * i as f32 / 4.;
            stroke(
                &mut f,
                Point::new(px, top),
                Point::new(px, bottom),
                Color { a: 0.065, ..CYAN },
                0.7,
            );
        }
        match self {
            Self::Market {
                blocks,
                points,
                spot,
                through,
                span,
            } => {
                let first = blocks
                    .first()
                    .map(|b| b.header.height)
                    .into_iter()
                    .chain(points.first().map(|p| p.height))
                    .min()
                    .unwrap_or(*through);
                let from = first
                    .max(through.saturating_sub(span.saturating_sub(1)))
                    .min(through.saturating_sub(1));
                let end = (*through).max(from.saturating_add(1));
                let x = |height: u64| {
                    left + (right - left)
                        * ((height.saturating_sub(from)) as f64 / (end - from) as f64) as f32
                };
                let width = ((right - left) / (end - from + 1) as f32 * 0.6).clamp(1.0, 10.0);
                for block in blocks {
                    let Some(candle) = &block.candle else {
                        continue;
                    };
                    let px = x(block.header.height);
                    let color = if candle.close.cmp(candle.open).is_ge() {
                        GREEN
                    } else {
                        theme::DANGER
                    };
                    stroke(
                        &mut f,
                        Point::new(px, y(candle.high.value())),
                        Point::new(px, y(candle.low.value())),
                        color,
                        1.0,
                    );
                    let top = y(candle.open.value()).min(y(candle.close.value()));
                    let height = (y(candle.open.value()) - y(candle.close.value()))
                        .abs()
                        .max(2.0);
                    f.fill_rectangle(
                        Point::new(px - width / 2.0, top),
                        iced::Size::new(width, height),
                        color,
                    );
                }
                let mut previous = None;
                for point in points {
                    let position = Point::new(x(point.height), y(point.price.value()));
                    if let Some(previous) = previous {
                        stroke(&mut f, previous, position, CYAN, 1.5);
                    }
                    previous = Some(position);
                }
                stroke(
                    &mut f,
                    Point::new(left, y(*spot)),
                    Point::new(right, y(*spot)),
                    Color { a: 0.2, ..GREEN },
                    0.8,
                );
                let current = Point::new(x(*through), y(*spot));
                f.fill(
                    &canvas::Path::circle(current, 6.0),
                    Color { a: 0.15, ..GREEN },
                );
                f.fill(&canvas::Path::circle(current, 3.0), GREEN);
                caption(
                    &mut f,
                    "LIVE",
                    right + 9.0,
                    (y(*spot) - 18.0).max(top),
                    GREEN,
                );
                for i in 0..5 {
                    let height = from + (end - from) * i / 4;
                    caption(
                        &mut f,
                        format!("#{height}"),
                        (x(height) - 8.0).max(left),
                        bottom + 13.0,
                        DIM,
                    );
                }
                if let Some(mouse) = cursor
                    .position_in(bounds)
                    .filter(|p| p.x >= left && p.x <= right && p.y >= top && p.y <= bottom)
                {
                    let height = from
                        + (((mouse.x - left) / (right - left)) as f64 * (end - from) as f64).round()
                            as u64;
                    stroke(
                        &mut f,
                        Point::new(mouse.x, top),
                        Point::new(mouse.x, bottom),
                        Color { a: 0.5, ..DIM },
                        1.0,
                    );
                    let title = if let Some(point) = points.iter().find(|p| p.height == height) {
                        format!(
                            "#{height} · {:.8} NOID · current price",
                            point.price.value()
                        )
                    } else if let Some(candle) = blocks
                        .iter()
                        .find(|b| b.header.height == height)
                        .and_then(|b| b.candle.as_ref())
                    {
                        format!(
                            "#{height} · {:.8} NOID · {} trades",
                            candle.close.value(),
                            candle.trades
                        )
                    } else {
                        format!("#{height}")
                    };
                    caption(&mut f, title, left + 6.0, 5.0, theme::TEXT);
                }
            }
            Self::Curve(definition, sold) => {
                let x = |q: u64| {
                    left + (right - left) * (q as f64 / definition.sale_units() as f64) as f32
                };
                let price = |q| {
                    definition
                        .marginal_price(q)
                        .ok()
                        .map(|p| p.numerator as f64 / p.denominator as f64)
                };
                if let (Some(start), Some(end), Some(current)) =
                    (price(0), price(definition.sale_units()), price(*sold))
                {
                    let from = Point::new(left, y(start));
                    let to = Point::new(right, y(end));
                    let area = canvas::Path::new(|p| {
                        p.move_to(Point::new(left, bottom));
                        p.line_to(from);
                        p.line_to(to);
                        p.line_to(Point::new(right, bottom));
                        p.close();
                    });
                    f.fill(&area, Color { a: 0.065, ..CYAN });
                    stroke(&mut f, from, to, Color { a: 0.10, ..CYAN }, 8.);
                    stroke(&mut f, from, to, CYAN, 1.8);
                    let current = Point::new(x(*sold), y(current));
                    stroke(
                        &mut f,
                        Point::new(current.x, top),
                        Point::new(current.x, bottom),
                        Color { a: 0.35, ..GREEN },
                        1.,
                    );
                    f.fill(
                        &canvas::Path::circle(current, 7.),
                        Color { a: 0.15, ..GREEN },
                    );
                    f.fill(&canvas::Path::circle(current, 3.5), GREEN);
                    caption(
                        &mut f,
                        "CURRENT",
                        (current.x + 10.).min(right - 65.),
                        current.y - 18.,
                        GREEN,
                    );
                    caption(&mut f, "DEX", right - 23., y(end) - 18., CYAN);
                }
                for i in 0..5 {
                    let q = definition.sale_units() * i / 4;
                    caption(
                        &mut f,
                        format!("{:.0}", q as f64 / 1_000_000.),
                        (x(q) - 10.).max(left),
                        bottom + 13.,
                        DIM,
                    );
                }
                if let Some(mouse) = cursor
                    .position_in(bounds)
                    .filter(|p| p.x >= left && p.x <= right && p.y >= top && p.y <= bottom)
                {
                    let q = (((mouse.x - left) / (right - left)) as f64
                        * definition.sale_units() as f64) as u64;
                    if let Some(p) = price(q) {
                        stroke(
                            &mut f,
                            Point::new(mouse.x, top),
                            Point::new(mouse.x, bottom),
                            Color { a: 0.5, ..DIM },
                            1.,
                        );
                        caption(
                            &mut f,
                            format!("{:.2} sold · {p:.8} NOID", q as f64 / 1_000_000.),
                            left + 6.,
                            5.,
                            theme::TEXT,
                        );
                    }
                }
            }
        }
        vec![f.into_geometry()]
    }
}

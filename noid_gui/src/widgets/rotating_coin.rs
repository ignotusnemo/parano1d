// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use iced::alignment;
use iced::widget::canvas;
use iced::{Color, Pixels, Point, Rectangle, Renderer, Theme, Vector};

use crate::theme;

#[derive(Clone)]
pub struct RotatingCoin {
    angle: f32,
    diameter: f32,
    depth: f32,
}

impl RotatingCoin {
    pub fn new(angle: f32, diameter: f32, depth: f32) -> Self {
        Self {
            angle,
            diameter,
            depth,
        }
    }
}

impl<Message> canvas::Program<Message> for RotatingCoin {
    type State = ();

    fn draw(
        &self,
        _state: &Self::State,
        renderer: &Renderer,
        _theme: &Theme,
        bounds: Rectangle,
        _cursor: iced::mouse::Cursor,
    ) -> Vec<canvas::Geometry> {
        let mut frame = canvas::Frame::new(renderer, bounds.size());
        let center = Point::new(bounds.width * 0.5, bounds.height * 0.5);
        draw_coin(
            &mut frame,
            center,
            self.diameter.min(bounds.width).min(bounds.height),
            self.depth,
            self.angle,
        );
        vec![frame.into_geometry()]
    }
}

fn draw_coin(frame: &mut canvas::Frame, center: Point, diameter: f32, depth: f32, angle: f32) {
    let cosine = angle.cos();
    let sine = angle.sin();
    let face_scale = cosine.abs().max(0.018);

    const LAYERS: usize = 11;
    for order in 0..LAYERS {
        let index = if cosine >= 0.0 {
            order
        } else {
            LAYERS - 1 - order
        };
        let position = index as f32 / (LAYERS - 1) as f32 - 0.5;
        let shift = position * depth * sine;
        let edge_light = (1.0 - position.abs() * 1.25).max(0.0);
        draw_symbol(
            frame,
            Point::new(center.x + shift, center.y),
            face_scale,
            diameter,
            Color::from_rgb(
                0.035 + edge_light * 0.035,
                0.16 + edge_light * 0.12,
                0.09 + edge_light * 0.07,
            ),
        );
    }

    if face_scale > 0.025 {
        let visible_z = if cosine >= 0.0 { 0.5 } else { -0.5 };
        draw_symbol(
            frame,
            Point::new(center.x + visible_z * depth * sine, center.y),
            face_scale,
            diameter,
            theme::ACCENT,
        );
    }
}

fn draw_symbol(
    frame: &mut canvas::Frame,
    center: Point,
    face_scale: f32,
    diameter: f32,
    color: Color,
) {
    frame.with_save(|frame| {
        frame.translate(Vector::new(center.x, center.y));
        frame.scale_nonuniform(Vector::new(face_scale, 1.0));
        frame.fill_text(canvas::Text {
            content: "①".into(),
            position: Point::new(-0.5, -2.0),
            color,
            size: Pixels(diameter * 0.88),
            font: theme::SYMBOL_FONT,
            align_x: alignment::Horizontal::Center.into(),
            align_y: alignment::Vertical::Center,
            ..canvas::Text::default()
        });
    });
}

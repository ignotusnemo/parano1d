// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use iced::alignment;
use iced::border::Radius;
use iced::widget::canvas;
use iced::{Color, Point, Rectangle, Renderer, Size, Theme, Vector};

use crate::app::Message;
use crate::theme;

const DESIGN_WIDTH: f32 = 820.0;
const DESIGN_HEIGHT: f32 = 350.0;
const BUTTON_CENTER_X: f32 = 350.0;
const BUTTON_DESIGN_WIDTH: f32 = 238.0;
const FLOOR_Y: f32 = 329.0;
const BLOCK_SOURCE_Y: f32 = -94.0;
const CHARACTER_SCALE: f32 = 1.35;
const CHARACTER_SCALE_ANCHOR_X: f32 = BUTTON_CENTER_X;
const HAMMER_READY_ANGLE: f32 = 4.48;
const HAMMER_WINDUP_ANGLE: f32 = 4.78;
const HAMMER_STRIKE_ANGLE: f32 = 3.16;
const INTRO_END: f32 = 7.4;
const FORGE_CYCLE: f32 = 7.2;
const STRIKE_DURATION: f32 = 1.30;
const STRIKE_COUNT: usize = 3;
const STRIKES_END: f32 = STRIKE_DURATION * STRIKE_COUNT as f32;
const DROP_START: f32 = 4.35;
const DROP_END: f32 = 5.15;

#[derive(Debug, Clone, Copy)]
pub struct LanguageForge {
    elapsed_seconds: f32,
    compact: bool,
}

#[derive(Debug, Default)]
pub struct LanguageForgeState {
    grid: canvas::Cache,
    shadows: canvas::Cache,
    floor_light: canvas::Cache,
    button_lights: [canvas::Cache; 3],
}

impl LanguageForge {
    pub fn new(elapsed_seconds: f32, compact: bool) -> Self {
        Self {
            elapsed_seconds: elapsed_seconds.max(0.0),
            compact,
        }
    }

    pub fn selector_position(
        width: f32,
        height: f32,
        compact: bool,
        selector_width: f32,
        selector_height: f32,
    ) -> Point {
        let layout = SceneLayout::new(width, height, compact);
        Point::new(
            layout.origin.x + BUTTON_CENTER_X * layout.scale - selector_width * 0.5,
            layout.origin.y + FLOOR_Y * layout.scale - selector_height,
        )
    }

    pub fn interface_offset(elapsed_seconds: f32) -> Vector {
        let state = forge_state(elapsed_seconds.max(0.0));
        let strength = state.shake_strength();
        Vector::new(
            (state.t * 181.0).sin() * 4.4 * strength,
            (state.t * 233.0).sin() * 2.8 * strength,
        )
    }
}

impl canvas::Program<Message> for LanguageForge {
    type State = LanguageForgeState;

    fn draw(
        &self,
        program_state: &Self::State,
        renderer: &Renderer,
        _theme: &Theme,
        bounds: Rectangle,
        _cursor: iced::mouse::Cursor,
    ) -> Vec<canvas::Geometry> {
        let layout = SceneLayout::new(bounds.width, bounds.height, self.compact);
        let entry_x = CHARACTER_SCALE_ANCHOR_X
            + (layout.right_edge_design + 35.0 - CHARACTER_SCALE_ANCHOR_X) / CHARACTER_SCALE;
        let state = forge_state_with_entry(self.elapsed_seconds, entry_x);
        let grid = program_state.grid.draw(renderer, bounds.size(), |frame| {
            with_scene_layout(frame, layout, draw_stage_grid_base);
        });
        let mut rings = canvas::Frame::new(renderer, bounds.size());
        with_scene_layout(&mut rings, layout, |frame| {
            draw_stage_rings(frame, state);
        });
        let shadows = program_state
            .shadows
            .draw(renderer, bounds.size(), |frame| {
                with_scene_layout(frame, layout, draw_selector_shadows);
            });
        let impact = selector_impact(state);
        let floor_light = if impact <= 0.0 {
            program_state
                .floor_light
                .draw(renderer, bounds.size(), |frame| {
                    with_scene_layout(frame, layout, draw_selector_floor_light_base);
                })
        } else {
            let mut floor_light = canvas::Frame::new(renderer, bounds.size());
            with_scene_layout(&mut floor_light, layout, |frame| {
                draw_selector_floor_light(frame, state);
            });
            floor_light.into_geometry()
        };
        let mut geometries = Vec::with_capacity(11);
        geometries.push(grid);
        geometries.push(rings.into_geometry());
        geometries.push(shadows);
        geometries.push(floor_light);

        for (index, (center_y, color)) in selector_button_lights().into_iter().enumerate() {
            let button_light =
                program_state.button_lights[index].draw(renderer, bounds.size(), |frame| {
                    with_scene_layout(frame, layout, |frame| {
                        draw_selector_button_light(frame, center_y, color);
                    });
                });
            geometries.push(button_light);

            if impact > 0.0 {
                let mut overlay = canvas::Frame::new(renderer, bounds.size());
                with_scene_layout(&mut overlay, layout, |frame| {
                    draw_selector_button_light_overlay(frame, state, center_y, color);
                });
                geometries.push(overlay.into_geometry());
            }
        }

        let mut scene = canvas::Frame::new(renderer, bounds.size());

        with_scene_layout(&mut scene, layout, |frame| {
            draw_selector_impact_light(frame, state);

            let strength = state.shake_strength();
            let shake = Vector::new(
                (state.t * 181.0).sin() * 2.8 * strength,
                (state.t * 233.0).sin() * 1.7 * strength,
            );
            frame.with_save(|frame| {
                frame.translate(shake);
                draw_blocks(frame, state);
                frame.with_save(|frame| {
                    frame.translate(Vector::new(CHARACTER_SCALE_ANCHOR_X, FLOOR_Y));
                    frame.scale(CHARACTER_SCALE);
                    frame.translate(Vector::new(-CHARACTER_SCALE_ANCHOR_X, -FLOOR_Y));
                    if state.smithing {
                        draw_operator(frame, state);
                    } else {
                        draw_traveler(frame, state);
                    }
                });
                draw_impact(frame, state);
            });
        });

        geometries.push(scene.into_geometry());
        geometries
    }
}

fn with_scene_layout(
    frame: &mut canvas::Frame,
    layout: SceneLayout,
    draw: impl FnOnce(&mut canvas::Frame),
) {
    frame.with_save(|frame| {
        frame.translate(layout.origin);
        frame.scale(layout.scale);
        draw(frame);
    });
}

#[derive(Debug, Clone, Copy)]
struct SceneLayout {
    scale: f32,
    origin: Vector,
    right_edge_design: f32,
}

impl SceneLayout {
    fn new(width: f32, height: f32, compact: bool) -> Self {
        let scale = if compact {
            170.0 / BUTTON_DESIGN_WIDTH
        } else {
            180.0 / BUTTON_DESIGN_WIDTH
        };
        let vertical_offset = if compact { 18.0 } else { 20.0 };
        let origin = Vector::new(
            (width - DESIGN_WIDTH * scale) * 0.5,
            (height - DESIGN_HEIGHT * scale) * 0.5 + vertical_offset,
        );
        Self {
            scale,
            origin,
            right_edge_design: (width - origin.x) / scale,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct ForgeState {
    t: f32,
    body_x: f32,
    moving: bool,
    walk_clock: f32,
    sigh_amount: f32,
    sigh_progress: Option<f32>,
    prepare: f32,
    smithing: bool,
    hammer_angle: f32,
    hammer_drop: f32,
    hammer_target_y: f32,
    body_lean: f32,
    impact: f32,
    spark_progress: Option<f32>,
    compression: f32,
    impact_y: f32,
    drop_progress: Option<f32>,
    landing: f32,
    surprise: f32,
    eye_open: f32,
}

impl ForgeState {
    fn shake_strength(self) -> f32 {
        (self.impact * 1.65).max(self.landing * 0.82)
    }
}

fn forge_state(elapsed: f32) -> ForgeState {
    forge_state_with_entry(elapsed, 850.0)
}

fn forge_state_with_entry(elapsed: f32, entry_x: f32) -> ForgeState {
    if elapsed < INTRO_END {
        return intro_state(elapsed, entry_x);
    }

    let cycle = (elapsed - INTRO_END).rem_euclid(FORGE_CYCLE);
    let mut state = ForgeState {
        t: elapsed,
        body_x: 486.0,
        moving: false,
        walk_clock: 0.0,
        sigh_amount: 0.0,
        sigh_progress: None,
        prepare: 1.0,
        smithing: true,
        hammer_angle: HAMMER_READY_ANGLE,
        hammer_drop: 0.0,
        hammer_target_y: 150.0,
        body_lean: 0.0,
        impact: 0.0,
        spark_progress: None,
        compression: 0.0,
        impact_y: 119.0,
        drop_progress: None,
        landing: 0.0,
        surprise: surprise_amount(cycle),
        eye_open: surprise_eye_openness(cycle),
    };

    if cycle < STRIKES_END {
        let strike_index = (cycle / STRIKE_DURATION).floor() as usize;
        let strike_index = strike_index.min(STRIKE_COUNT - 1);
        let phase = (cycle - strike_index as f32 * STRIKE_DURATION) / STRIKE_DURATION;
        state.hammer_target_y = [150.0, 158.0, 166.0][strike_index];
        state.impact_y = [119.0, 130.0, 142.0][strike_index];

        if phase < 0.30 {
            let amount = smoothstep(phase / 0.30);
            state.hammer_angle = lerp(HAMMER_READY_ANGLE, HAMMER_WINDUP_ANGLE, amount);
            state.body_lean = lerp(0.0, 13.0, amount);
        } else if phase < 0.54 {
            let amount = (phase - 0.30) / 0.24;
            let swing = amount.powf(3.4);
            state.hammer_angle = lerp(HAMMER_WINDUP_ANGLE, HAMMER_STRIKE_ANGLE, swing);
            state.hammer_drop = swing;
            state.body_lean = lerp(13.0, -9.0, amount.powf(2.2));
        } else if phase < 0.69 {
            let amount = smoothstep((phase - 0.54) / 0.15);
            state.hammer_angle = lerp(HAMMER_STRIKE_ANGLE, 3.68, amount);
            state.hammer_drop = lerp(1.0, 0.78, amount);
            state.body_lean = lerp(-9.0, -2.0, amount);
        } else {
            let amount = smoothstep((phase - 0.69) / 0.31);
            state.body_lean = lerp(-2.0, 0.0, amount);
            if strike_index == STRIKE_COUNT - 1 {
                state.hammer_angle = lerp(3.68, HAMMER_STRIKE_ANGLE, amount);
                state.hammer_drop = lerp(0.78, 1.0, amount);
            } else {
                state.hammer_angle = lerp(3.68, HAMMER_READY_ANGLE, amount);
                state.hammer_drop = lerp(0.78, 0.0, amount);
            }
        }

        if (0.54..0.76).contains(&phase) {
            state.impact = 1.0 - smoothstep((phase - 0.54) / 0.22);
        }
        if (0.54..0.88).contains(&phase) {
            state.spark_progress = Some((phase - 0.54) / 0.34);
        }
        let crush = if phase < 0.54 {
            0.0
        } else {
            smoothstep((phase - 0.54) / 0.12)
        };
        state.compression = strike_index as f32 + crush;
    } else if cycle < DROP_START {
        state.hammer_angle = HAMMER_STRIKE_ANGLE;
        state.hammer_drop = 1.0;
        state.hammer_target_y = 166.0;
        state.impact_y = 142.0;
        state.compression = 3.0;
    } else if cycle < DROP_END {
        let progress = (cycle - DROP_START) / (DROP_END - DROP_START);
        let settle = smoothstep(progress / 0.62);
        state.hammer_angle = lerp(HAMMER_STRIKE_ANGLE, HAMMER_READY_ANGLE, settle);
        state.hammer_drop = 1.0;
        state.hammer_target_y = lerp(166.0, 205.0, settle);
        state.compression = 3.0;
        state.drop_progress = Some(progress);
        if progress >= 0.78 {
            state.landing = 1.0 - smoothstep((progress - 0.78) / 0.22);
        }
    } else {
        let ready = smoothstep((cycle - 6.05) / (FORGE_CYCLE - 6.05));
        state.hammer_angle = HAMMER_READY_ANGLE;
        state.hammer_drop = lerp(1.0, 0.0, ready);
        state.hammer_target_y = 205.0;
        state.body_lean = 0.0;
        state.compression = 0.0;
    }

    state
}

fn intro_state(t: f32, entry_x: f32) -> ForgeState {
    let first_walk_end = 3.25;
    let pause_end = 4.10;
    let second_walk_end = 6.58;
    let pause_x = lerp(entry_x, 505.0, 0.63);
    let mut moving = false;
    let body_x;
    let walk_clock;

    if t < first_walk_end {
        body_x = lerp(entry_x, pause_x, smoothstep(t / first_walk_end));
        moving = true;
        walk_clock = t;
    } else if t < pause_end {
        body_x = pause_x;
        walk_clock = first_walk_end;
    } else if t < second_walk_end {
        body_x = lerp(
            pause_x,
            505.0,
            smoothstep((t - pause_end) / (second_walk_end - pause_end)),
        );
        moving = true;
        walk_clock = first_walk_end + t - pause_end;
    } else {
        body_x = lerp(
            505.0,
            486.0,
            smoothstep((t - second_walk_end) / (INTRO_END - second_walk_end)),
        );
        walk_clock = first_walk_end + second_walk_end - pause_end;
    }

    let pause = ((t - first_walk_end) / (pause_end - first_walk_end)).clamp(0.0, 1.0);
    let sigh_amount = if t < first_walk_end || t >= pause_end {
        0.0
    } else if pause < 0.32 {
        smoothstep(pause / 0.32)
    } else if pause < 0.70 {
        1.0
    } else {
        1.0 - smoothstep((pause - 0.70) / 0.30)
    };
    let sigh_progress = (3.48..=4.02).contains(&t).then(|| (t - 3.48) / 0.54);

    ForgeState {
        t,
        body_x,
        moving,
        walk_clock,
        sigh_amount,
        sigh_progress,
        prepare: smoothstep((t - second_walk_end) / (INTRO_END - second_walk_end)),
        smithing: false,
        hammer_angle: HAMMER_READY_ANGLE,
        hammer_drop: 0.0,
        hammer_target_y: 150.0,
        body_lean: 0.0,
        impact: 0.0,
        spark_progress: None,
        compression: 0.0,
        impact_y: 119.0,
        drop_progress: None,
        landing: 0.0,
        surprise: 0.0,
        eye_open: 1.0,
    }
}

fn surprise_amount(cycle: f32) -> f32 {
    if !(4.86..6.25).contains(&cycle) {
        0.0
    } else if cycle < 5.18 {
        smoothstep((cycle - 4.86) / 0.32)
    } else if cycle < 5.72 {
        1.0
    } else {
        1.0 - smoothstep((cycle - 5.72) / 0.53)
    }
}

fn surprise_eye_openness(cycle: f32) -> f32 {
    let blink = |center: f32| (1.0 - ((cycle - center).abs() / 0.11).clamp(0.0, 1.0)).powi(2);
    1.0 - blink(5.30).max(blink(5.67)) * 0.94
}

fn selector_impact(state: ForgeState) -> f32 {
    state.impact.max(state.landing * 0.56)
}

fn draw_selector_shadows(frame: &mut canvas::Frame) {
    soft_ellipse_glow(
        frame,
        Point::new(BUTTON_CENTER_X + 3.0, FLOOR_Y + 8.0),
        Vector::new(142.0, 13.0),
        Color::from_rgb8(2, 3, 8),
        0.72,
    );
    soft_ellipse_glow(
        frame,
        Point::new(535.0, FLOOR_Y + 8.0),
        Vector::new(86.0, 10.0),
        Color::from_rgb8(2, 3, 8),
        0.62,
    );
}

fn draw_selector_floor_light_base(frame: &mut canvas::Frame) {
    soft_ellipse_glow(
        frame,
        Point::new(BUTTON_CENTER_X, FLOOR_Y + 5.0),
        Vector::new(112.0, 7.0),
        theme::DANGER,
        0.030,
    );
}

fn draw_selector_floor_light(frame: &mut canvas::Frame, state: ForgeState) {
    let impact = selector_impact(state);
    soft_ellipse_glow(
        frame,
        Point::new(BUTTON_CENTER_X, FLOOR_Y + 5.0),
        Vector::new(112.0 + impact * 18.0, 7.0 + impact * 2.0),
        theme::DANGER,
        0.030 + impact * 0.048,
    );
}

fn selector_button_lights() -> [(f32, Color); 3] {
    [
        (180.0, theme::ACCENT),
        (242.0, theme::CYAN),
        (304.0, theme::DANGER),
    ]
}

fn draw_selector_button_light(frame: &mut canvas::Frame, center_y: f32, color: Color) {
    soft_ellipse_glow(
        frame,
        Point::new(BUTTON_CENTER_X, center_y + 5.0),
        Vector::new(132.0, 39.0),
        color,
        0.032,
    );
}

fn draw_selector_button_light_overlay(
    frame: &mut canvas::Frame,
    state: ForgeState,
    center_y: f32,
    color: Color,
) {
    let impact = selector_impact(state);
    soft_ellipse_glow_overlay(
        frame,
        Point::new(BUTTON_CENTER_X, center_y + 5.0),
        Vector::new(132.0, 39.0),
        color,
        0.032,
        0.032 + impact * 0.014,
    );
}

fn draw_selector_impact_light(frame: &mut canvas::Frame, state: ForgeState) {
    let impact = selector_impact(state);
    if impact <= 0.0 {
        return;
    }

    soft_ellipse_glow(
        frame,
        Point::new(BUTTON_CENTER_X, 157.0),
        Vector::new(120.0 + impact * 28.0, 45.0 + impact * 10.0),
        theme::CYAN,
        impact * 0.072,
    );
}

fn active_block_generation(state: ForgeState) -> u64 {
    if state.t < INTRO_END {
        return 0;
    }

    let elapsed = state.t - INTRO_END;
    let cycle_number = (elapsed / FORGE_CYCLE).floor() as u64;
    let cycle = elapsed.rem_euclid(FORGE_CYCLE);
    cycle_number + u64::from(cycle >= DROP_START)
}

fn block_color_palette(generation: u64) -> [Color; 3] {
    const PERMUTATIONS: [[usize; 3]; 6] = [
        [2, 0, 1],
        [0, 2, 1],
        [1, 0, 2],
        [2, 1, 0],
        [0, 1, 2],
        [1, 2, 0],
    ];
    let palette = [theme::ACCENT, theme::CYAN, theme::DANGER];
    let order = PERMUTATIONS[(generation as usize).wrapping_mul(5).wrapping_add(2) % 6];
    [palette[order[0]], palette[order[1]], palette[order[2]]]
}

fn draw_stage_grid_base(frame: &mut canvas::Frame) {
    for y in (-32..=304).step_by(42) {
        let line = canvas::Path::line(Point::new(84.0, y as f32), Point::new(616.0, y as f32));
        frame.stroke(
            &line,
            canvas::Stroke::default()
                .with_width(1.0)
                .with_color(with_alpha(theme::CYAN, 0.040)),
        );
    }
    for x in (110..=590).step_by(60) {
        let line = canvas::Path::line(Point::new(x as f32, -38.0), Point::new(x as f32, 340.0));
        frame.stroke(
            &line,
            canvas::Stroke::default()
                .with_width(1.0)
                .with_color(with_alpha(theme::PROOF, 0.032)),
        );
    }
}

fn draw_stage_rings(frame: &mut canvas::Frame, state: ForgeState) {
    let pulse = 0.5 + 0.5 * (state.t * 2.1).sin();
    for (radius, color, alpha) in [
        (94.0 + pulse * 3.0, theme::PROOF, 0.046),
        (126.0 + pulse * 2.0, theme::CYAN, 0.026),
        (168.0 + pulse, theme::ACCENT, 0.012),
    ] {
        let ring = canvas::Path::circle(Point::new(BUTTON_CENTER_X, 174.0), radius);
        frame.stroke(
            &ring,
            canvas::Stroke::default()
                .with_width(1.0)
                .with_color(with_alpha(color, alpha)),
        );
    }
}

fn draw_blocks(frame: &mut canvas::Frame, state: ForgeState) {
    let generation = active_block_generation(state);
    if let Some(progress) = state.drop_progress {
        let old_alpha = 1.0 - smoothstep(progress / 0.76);
        draw_block_pile(
            frame,
            3.0,
            state,
            generation.saturating_sub(1),
            old_alpha,
            None,
        );
        draw_block_pile(frame, 0.0, state, generation, 1.0, Some(progress));
    } else {
        draw_block_pile(frame, state.compression, state, generation, 1.0, None);
    }
}

fn draw_block_pile(
    frame: &mut canvas::Frame,
    compression: f32,
    state: ForgeState,
    generation: u64,
    alpha: f32,
    fall_progress: Option<f32>,
) {
    type BlockPlacement = (f32, f32, f32, f32, f32);
    const STAGE_ZERO: [[BlockPlacement; 3]; 3] = [
        [
            (301.0, 114.0, 36.0, 36.0, -0.58),
            (365.0, 119.0, 36.0, 36.0, 0.0),
            (332.0, 84.0, 36.0, 36.0, 0.14),
        ],
        [
            (303.0, 119.0, 36.0, 36.0, 0.0),
            (360.0, 114.0, 36.0, 36.0, 0.58),
            (330.0, 84.0, 36.0, 36.0, -0.17),
        ],
        [
            (308.0, 113.0, 36.0, 36.0, -0.70),
            (359.0, 119.0, 36.0, 36.0, 0.0),
            (334.0, 83.0, 36.0, 36.0, 0.24),
        ],
    ];
    const STAGE_ONE: [[BlockPlacement; 3]; 3] = [
        [
            (304.0, 126.0, 36.0, 28.0, -0.30),
            (364.0, 130.0, 36.0, 25.0, 0.0),
            (333.0, 105.0, 36.0, 25.0, 0.08),
        ],
        [
            (304.0, 130.0, 36.0, 25.0, 0.0),
            (361.0, 126.0, 36.0, 28.0, 0.30),
            (332.0, 105.0, 36.0, 25.0, -0.08),
        ],
        [
            (309.0, 125.0, 36.0, 29.0, -0.34),
            (360.0, 130.0, 36.0, 25.0, 0.0),
            (334.0, 104.0, 36.0, 25.0, 0.12),
        ],
    ];
    const STAGE_TWO: [(f32, f32, f32, f32, f32); 3] = [
        (302.0, 141.0, 34.0, 14.0, -0.04),
        (337.0, 141.0, 34.0, 14.0, 0.0),
        (372.0, 141.0, 34.0, 14.0, 0.04),
    ];
    const DROP_ORDERS: [[usize; 3]; 3] = [[2, 0, 1], [1, 2, 0], [0, 2, 1]];
    const SPAWN_X: [[f32; 3]; 3] = [
        [284.0, 397.0, 344.0],
        [397.0, 294.0, 351.0],
        [315.0, 405.0, 276.0],
    ];

    let compression = compression.clamp(0.0, 3.0);
    let merge = smoothstep(compression - 2.0);
    let jitter = state.impact * (state.t * 95.0).sin() * 1.15 * 1.65;
    let colors = block_color_palette(generation);
    let variant = generation as usize % STAGE_ZERO.len();

    frame.with_save(|frame| {
        frame.translate(Vector::new(jitter, 0.0));
        let mut modules = [(0.0, 0.0, 0.0, 0.0, 0.0); 3];
        let mut falling = [0.0; 3];
        for index in 0..3 {
            let (from, to, amount) = if compression < 1.0 {
                (
                    STAGE_ZERO[variant][index],
                    STAGE_ONE[variant][index],
                    smoothstep(compression),
                )
            } else if compression < 2.0 {
                (
                    STAGE_ONE[variant][index],
                    STAGE_TWO[index],
                    smoothstep(compression - 1.0),
                )
            } else {
                (STAGE_TWO[index], STAGE_TWO[index], 0.0)
            };
            let mut x = lerp(from.0, to.0, amount);
            let mut y = lerp(from.1, to.1, amount);
            let width = lerp(from.2, to.2, amount);
            let height = lerp(from.3, to.3, amount);
            let mut angle = lerp(from.4, to.4, amount);

            if let Some(progress) = fall_progress {
                let rank = DROP_ORDERS[variant]
                    .iter()
                    .position(|candidate| *candidate == index)
                    .unwrap_or(index);
                let delay = rank as f32 * 0.095;
                let fall = ease_out(((progress - delay) / (0.78 - delay)).clamp(0.0, 1.0));
                let arc = (fall * std::f32::consts::PI).sin();
                let lateral = (rank as f32 - 1.0) * 13.0;
                x = lerp(SPAWN_X[variant][index], x, fall) + arc * lateral;
                y = lerp(BLOCK_SOURCE_Y - rank as f32 * 13.0, y, fall);
                let spin = [2.7, -2.3, 3.1][(index + variant) % 3];
                angle += (1.0 - smoothstep(fall)) * spin;
                falling[index] = 1.0 - fall;
            }

            modules[index] = (x, y, width, height, angle);
        }

        for index in 0..3 {
            let (x, y, width, height, angle) = modules[index];
            draw_forge_block(
                frame,
                x,
                y,
                width,
                height,
                angle,
                index,
                colors[index],
                alpha,
                merge,
                falling[index],
            );
        }

        if merge > 0.0 {
            draw_forge_block(
                frame,
                326.0,
                141.0,
                52.0,
                14.0,
                0.0,
                0,
                theme::ACCENT,
                alpha * merge,
                0.0,
                0.0,
            );
        }
    });
}

#[allow(clippy::too_many_arguments)]
fn draw_forge_block(
    frame: &mut canvas::Frame,
    x: f32,
    y: f32,
    width: f32,
    height: f32,
    angle: f32,
    index: usize,
    accent: Color,
    alpha: f32,
    merge: f32,
    falling: f32,
) {
    if falling > 0.02 {
        let direction = if index.is_multiple_of(2) { -1.0 } else { 1.0 };
        let trail = canvas::Path::new(|path| {
            path.move_to(Point::new(
                x + width * 0.5 + direction * 7.0,
                y - 25.0 * falling,
            ));
            path.line_to(Point::new(x + width * 0.5 + direction * 2.0, y - 10.0));
        });
        frame.stroke(
            &trail,
            canvas::Stroke::default()
                .with_width(1.0)
                .with_color(with_alpha(accent, alpha * falling * 0.24))
                .with_line_cap(canvas::LineCap::Round),
        );
    }

    let solid_alpha = alpha * (1.0 - merge);
    let edge_alpha = alpha * (1.0 - merge);
    if solid_alpha <= 0.001 {
        return;
    }

    let center = Point::new(x + width * 0.5, y + height * 0.5);
    let radius = (width.min(height) * 0.16).clamp(1.6, 5.5);
    let depth = (height * 0.10).clamp(1.4, 3.8);

    frame.with_save(|frame| {
        frame.translate(Vector::new(center.x, center.y));
        frame.rotate(angle);
        frame.translate(Vector::new(-center.x, -center.y));

        let broad_shadow = canvas::Path::rounded_rectangle(
            Point::new(x + 1.8, y + depth + 4.2),
            Size::new(width, height),
            Radius::from(radius),
        );
        frame.fill(
            &broad_shadow,
            Color::from_rgba8(1, 2, 7, solid_alpha * 0.32),
        );

        for layer in (1..=3).rev() {
            let offset = depth * layer as f32 / 3.0;
            let edge = canvas::Path::rounded_rectangle(
                Point::new(x + 0.5, y + offset),
                Size::new(width, height),
                Radius::from(radius),
            );
            frame.fill(
                &edge,
                with_alpha(
                    mix_color(accent, Color::BLACK, 0.38 + layer as f32 * 0.035),
                    solid_alpha,
                ),
            );
        }

        let face = canvas::Path::rounded_rectangle(
            Point::new(x, y),
            Size::new(width, height),
            Radius::from(radius),
        );
        let gradient = canvas::gradient::Linear::new(
            Point::new(center.x, y + height),
            Point::new(center.x, y),
        )
        .add_stop(
            0.0,
            with_alpha(mix_color(accent, Color::BLACK, 0.17), solid_alpha),
        )
        .add_stop(0.48, with_alpha(accent, solid_alpha))
        .add_stop(
            1.0,
            with_alpha(mix_color(accent, Color::WHITE, 0.18), solid_alpha),
        );
        frame.fill(&face, gradient);
        frame.stroke(
            &face,
            canvas::Stroke::default()
                .with_width(1.05)
                .with_color(with_alpha(
                    mix_color(accent, Color::WHITE, 0.54),
                    edge_alpha * 0.68,
                )),
        );

        let top_glint = canvas::Path::new(|path| {
            path.move_to(Point::new(x + radius + 1.5, y + 2.2));
            path.line_to(Point::new(
                x + width - radius - 1.5,
                y + 2.2 + index as f32 * 0.12,
            ));
        });
        frame.stroke(
            &top_glint,
            canvas::Stroke::default()
                .with_width(0.9)
                .with_color(with_alpha(Color::WHITE, edge_alpha * 0.34))
                .with_line_cap(canvas::LineCap::Round),
        );

        if width >= 19.0 && height >= 13.0 {
            let symbol_size = iced::Pixels((height * 0.48).clamp(7.0, 16.0));
            frame.fill_text(canvas::Text {
                content: "①".into(),
                position: Point::new(center.x + 0.9, center.y + 1.2),
                color: with_alpha(mix_color(accent, Color::BLACK, 0.72), edge_alpha * 0.48),
                size: symbol_size,
                font: theme::SYMBOL_FONT,
                align_x: alignment::Horizontal::Center.into(),
                align_y: alignment::Vertical::Center,
                ..canvas::Text::default()
            });
            frame.fill_text(canvas::Text {
                content: "①".into(),
                position: Point::new(center.x - 0.25, center.y - 0.45),
                color: with_alpha(mix_color(accent, Color::WHITE, 0.88), edge_alpha * 0.98),
                size: symbol_size,
                font: theme::SYMBOL_FONT,
                align_x: alignment::Horizontal::Center.into(),
                align_y: alignment::Vertical::Center,
                ..canvas::Text::default()
            });
        }
    });
}

#[derive(Debug, Clone, Copy)]
struct HammerRig {
    main_shoulder: Point,
    support_shoulder: Point,
    main_elbow: Point,
    support_elbow: Point,
    main_grip: Point,
    base_grip: Point,
    head: Point,
}

fn hammer_rig(state: ForgeState) -> HammerRig {
    hammer_rig_values(
        state.hammer_angle,
        state.hammer_drop,
        state.hammer_target_y,
        state.body_lean,
    )
}

fn hammer_rig_values(angle: f32, hammer_drop: f32, target_y: f32, body_lean: f32) -> HammerRig {
    let main_shoulder = Point::new(459.0 + body_lean, 174.0);
    let support_shoulder = Point::new(511.0 + body_lean, 174.0);
    let axis = Vector::new(angle.cos(), angle.sin());
    let base_grip = Point::new(
        lerp(431.0 + body_lean.max(0.0) * 0.75, 442.0, hammer_drop),
        lerp(179.0, target_y, hammer_drop),
    );
    let main_grip = Point::new(base_grip.x + axis.x * 20.0, base_grip.y + axis.y * 20.0);
    let head = Point::new(base_grip.x + axis.x * 72.0, base_grip.y + axis.y * 72.0);
    let main_elbow = elbow_between(main_shoulder, main_grip, -9.0);
    let support_elbow = elbow_between(support_shoulder, base_grip, -10.0);

    HammerRig {
        main_shoulder,
        support_shoulder,
        main_elbow,
        support_elbow,
        main_grip,
        base_grip,
        head,
    }
}

fn draw_operator(frame: &mut canvas::Frame, state: ForgeState) {
    let body_x = 486.0;
    let head = Point::new(
        lerp(479.0, 486.0, state.surprise) + state.body_lean,
        124.0 - state.surprise * 3.0,
    );
    let pelvis = Point::new(body_x, 259.0);

    stroke_limb(
        frame,
        &[
            Point::new(body_x + state.body_lean, 158.0),
            Point::new(body_x + state.body_lean * 0.55, 220.0),
            pelvis,
        ],
        theme::MUTED,
        with_alpha(theme::PROOF, 0.78),
        6.0,
    );
    stroke_limb(
        frame,
        &[pelvis, Point::new(455.0, 327.0)],
        theme::MUTED,
        with_alpha(theme::CYAN, 0.72),
        6.0,
    );
    stroke_limb(
        frame,
        &[pelvis, Point::new(520.0, 327.0)],
        theme::MUTED,
        with_alpha(theme::CYAN, 0.72),
        6.0,
    );
    stroke_line(
        frame,
        Point::new(443.0, 328.0),
        Point::new(465.0, 328.0),
        with_alpha(theme::TEXT, 0.62),
        4.0,
    );
    stroke_line(
        frame,
        Point::new(510.0, 328.0),
        Point::new(532.0, 328.0),
        with_alpha(theme::TEXT, 0.62),
        4.0,
    );

    let rig = hammer_rig(state);
    stroke_limb(
        frame,
        &[rig.main_shoulder, rig.main_elbow, rig.main_grip],
        theme::MUTED,
        with_alpha(theme::PROOF, 0.86),
        5.5,
    );

    stroke_limb(
        frame,
        &[rig.support_shoulder, rig.support_elbow, rig.base_grip],
        theme::MUTED,
        with_alpha(theme::ACCENT, 0.84),
        5.5,
    );

    for (point, color) in [
        (pelvis, theme::CYAN),
        (rig.main_shoulder, theme::PROOF),
        (rig.main_elbow, theme::PROOF),
        (rig.main_grip, theme::PROOF),
        (rig.support_elbow, theme::ACCENT),
        (rig.base_grip, theme::ACCENT),
    ] {
        draw_joint(frame, point, color);
    }

    draw_coin_head(frame, head, state.surprise, state.eye_open);
    draw_hammer(frame, rig.base_grip, rig.head, state.impact);
}

fn draw_traveler(frame: &mut canvas::Frame, state: ForgeState) {
    let transition = state.prepare;
    let phase = (state.walk_clock * std::f32::consts::TAU * 1.15).sin();
    let bob = if state.moving {
        (state.walk_clock * std::f32::consts::TAU * 1.15)
            .cos()
            .abs()
            * 3.0
    } else {
        0.0
    };
    let slump = state.sigh_amount * 7.0;
    let x = state.body_x;

    let pelvis = point_lerp(
        Point::new(x, 259.0 + bob + slump * 0.25),
        Point::new(486.0, 259.0),
        transition,
    );
    let middle = point_lerp(
        Point::new(x - 8.0, 220.0 + bob + slump * 0.65),
        Point::new(486.0, 220.0),
        transition,
    );
    let neck = point_lerp(
        Point::new(x - 17.0, 177.0 + bob + slump),
        Point::new(486.0, 158.0),
        transition,
    );
    let head = point_lerp(
        Point::new(x - 34.0, 139.0 + bob + slump * 1.10),
        Point::new(479.0, 124.0),
        transition,
    );
    let left_knee = point_lerp(
        Point::new(x - 13.0 + phase * 7.0, 293.0 + bob),
        Point::new(471.0, 293.0),
        transition,
    );
    let right_knee = point_lerp(
        Point::new(x + 13.0 - phase * 7.0, 293.0 + bob),
        Point::new(502.0, 293.0),
        transition,
    );
    let left_foot = point_lerp(
        Point::new(x - 24.0 + phase * 18.0, 328.0),
        Point::new(455.0, 327.0),
        transition,
    );
    let right_foot = point_lerp(
        Point::new(x + 25.0 - phase * 18.0, 328.0),
        Point::new(520.0, 327.0),
        transition,
    );

    stroke_limb(
        frame,
        &[neck, middle, pelvis],
        theme::MUTED,
        with_alpha(theme::PROOF, 0.70),
        6.0,
    );
    stroke_limb(
        frame,
        &[pelvis, left_knee, left_foot],
        theme::MUTED,
        with_alpha(theme::CYAN, 0.72),
        6.0,
    );
    stroke_limb(
        frame,
        &[pelvis, right_knee, right_foot],
        theme::MUTED,
        with_alpha(theme::CYAN, 0.72),
        6.0,
    );
    stroke_line(
        frame,
        Point::new(left_foot.x - 10.0, left_foot.y + 1.0),
        Point::new(left_foot.x + 11.0, left_foot.y + 1.0),
        with_alpha(theme::TEXT, 0.62),
        4.0,
    );
    stroke_line(
        frame,
        Point::new(right_foot.x - 10.0, right_foot.y + 1.0),
        Point::new(right_foot.x + 11.0, right_foot.y + 1.0),
        with_alpha(theme::TEXT, 0.62),
        4.0,
    );

    let target = hammer_rig_values(HAMMER_READY_ANGLE, 0.0, 150.0, 0.0);
    let walk_grip = Point::new(x + 34.0, 241.0 + bob + slump * 0.35);
    let drag_head = Point::new(x + 100.0, 302.0 + phase.abs() * 0.7);
    let base_grip = cubic_point(
        walk_grip,
        Point::new(x + 80.0, 150.0),
        Point::new(500.0, 150.0),
        target.base_grip,
        transition,
    );
    let hammer_head = cubic_point(
        drag_head,
        Point::new(x + 150.0, 80.0),
        Point::new(430.0, 70.0),
        target.head,
        transition,
    );
    let main_grip = point_lerp(base_grip, hammer_head, transition * 20.0 / 72.0);
    let main_shoulder = point_lerp(
        Point::new(x + 2.0, 188.0 + bob + slump),
        target.main_shoulder,
        transition,
    );
    let main_elbow = point_lerp(
        Point::new(x + 20.0, 216.0 + bob + slump * 0.70),
        target.main_elbow,
        transition,
    );
    let arm_swing = -phase * 10.0;
    let support_shoulder = point_lerp(
        Point::new(x - 33.0, 184.0 + bob + slump),
        target.support_shoulder,
        transition,
    );
    let support_elbow = point_lerp(
        Point::new(x - 48.0 + arm_swing, 218.0 + bob + slump * 0.70),
        target.support_elbow,
        transition,
    );
    let free_hand = Point::new(x - 56.0 + arm_swing * 1.35, 245.0 + bob + slump * 0.45);
    let support_hand = point_lerp(free_hand, base_grip, smoothstep((transition - 0.18) / 0.82));

    stroke_limb(
        frame,
        &[main_shoulder, main_elbow, main_grip],
        theme::MUTED,
        with_alpha(theme::PROOF, 0.86),
        5.5,
    );
    stroke_limb(
        frame,
        &[support_shoulder, support_elbow, support_hand],
        theme::MUTED,
        with_alpha(theme::ACCENT, 0.82),
        5.5,
    );
    draw_hammer(frame, base_grip, hammer_head, 0.0);

    for (point, color) in [
        (pelvis, theme::CYAN),
        (main_elbow, theme::PROOF),
        (main_grip, theme::PROOF),
        (support_elbow, theme::ACCENT),
        (support_hand, theme::ACCENT),
    ] {
        draw_joint(frame, point, color);
    }
    frame.with_save(|frame| {
        frame.translate(Vector::new(head.x, head.y));
        frame.rotate(lerp(-0.16 - state.sigh_amount * 0.06, 0.0, transition));
        draw_coin_head(frame, Point::ORIGIN, 0.0, 1.0);
    });

    if state.moving && transition < 0.18 {
        let pulse = 0.35
            + 0.65
                * (state.walk_clock * std::f32::consts::TAU * 1.15)
                    .sin()
                    .abs();
        for index in 0..3 {
            let x = hammer_head.x + 17.0 + index as f32 * 9.0;
            let y = 326.0 - index as f32 * 2.0;
            stroke_line(
                frame,
                Point::new(x - 5.0, y + 2.0),
                Point::new(x + 3.0, y),
                with_alpha(
                    if index == 1 {
                        theme::PROOF
                    } else {
                        theme::CYAN
                    },
                    pulse * (0.30 - index as f32 * 0.06),
                ),
                1.0,
            );
        }
    }

    if let Some(progress) = state.sigh_progress {
        for index in 0..3 {
            let amount = (progress * 1.22 - index as f32 * 0.18).clamp(0.0, 1.0);
            let fade = (amount * std::f32::consts::PI).sin();
            if fade <= 0.0 {
                continue;
            }
            let point = Point::new(
                head.x - 18.0 - amount * 38.0,
                head.y + 3.0 - (amount * std::f32::consts::PI).sin() * 8.0 + index as f32 * 2.0,
            );
            let particle = canvas::Path::circle(point, 2.2 - index as f32 * 0.35);
            frame.fill(
                &particle,
                with_alpha(
                    if index == 1 {
                        theme::PROOF
                    } else {
                        theme::CYAN
                    },
                    fade * 0.62,
                ),
            );
        }
    }
}

fn draw_coin_head(frame: &mut canvas::Frame, center: Point, surprise: f32, eye_open: f32) {
    let radius_x = lerp(18.0, 23.0, surprise);
    let radius_y = 23.0;
    fill_ellipse(
        frame,
        center,
        Vector::new(radius_x + 12.0, radius_y + 12.0),
        with_alpha(theme::ACCENT, 0.045 + surprise * 0.075),
    );
    fill_ellipse(
        frame,
        Point::new(center.x + 1.5, center.y + 2.0),
        Vector::new(radius_x + 2.5, radius_y + 2.5),
        Color::from_rgba8(3, 5, 10, 0.64),
    );
    fill_ellipse(
        frame,
        center,
        Vector::new(radius_x, radius_y),
        Color::from_rgb8(44, 48, 62),
    );
    fill_ellipse(
        frame,
        Point::new(center.x - 2.5, center.y - 4.0),
        Vector::new(radius_x - 2.8, radius_y - 3.8),
        with_alpha(theme::MUTED, 0.095),
    );
    fill_ellipse(
        frame,
        Point::new(center.x + 3.0, center.y + 5.0),
        Vector::new(radius_x - 3.0, radius_y - 4.0),
        with_alpha(theme::INK, 0.20),
    );
    stroke_ellipse(
        frame,
        center,
        Vector::new(radius_x, radius_y),
        canvas::Stroke::default()
            .with_width(1.5)
            .with_color(with_alpha(
                if surprise > 0.5 {
                    theme::ACCENT
                } else {
                    theme::CYAN
                },
                0.78,
            )),
    );
    stroke_ellipse(
        frame,
        center,
        Vector::new((radius_x - 7.0).max(8.0), radius_y - 7.0),
        canvas::Stroke::default()
            .with_width(1.0)
            .with_color(with_alpha(theme::PROOF, 0.46 + surprise * 0.22)),
    );
    frame.fill_text(canvas::Text {
        content: "1".into(),
        position: Point::new(center.x, center.y + 0.5),
        color: with_alpha(theme::TEXT, 1.0 - surprise),
        size: iced::Pixels(18.0 + surprise * 1.5),
        font: theme::BRAND_FONT,
        align_x: iced::alignment::Horizontal::Center.into(),
        align_y: alignment::Vertical::Center,
        ..canvas::Text::default()
    });

    if surprise > 0.05 {
        let eye_height = 1.0 + 5.0 * eye_open;
        for x in [-7.0, 7.0] {
            let eye = canvas::Path::rounded_rectangle(
                Point::new(center.x + x - 3.2, center.y - 4.0 - eye_height * 0.5),
                Size::new(6.4, eye_height),
                Radius::from(3.0),
            );
            frame.fill(&eye, with_alpha(theme::TEXT, surprise * 0.92));
            if eye_open > 0.38 {
                let pupil = canvas::Path::circle(Point::new(center.x + x, center.y - 4.0), 1.35);
                frame.fill(&pupil, with_alpha(theme::INK, surprise * eye_open));
            }
        }
    }
}

fn draw_hammer(frame: &mut canvas::Frame, base_grip: Point, head: Point, impact: f32) {
    stroke_line(
        frame,
        Point::new(base_grip.x + 2.0, base_grip.y + 3.0),
        Point::new(head.x + 2.0, head.y + 3.0),
        Color::from_rgba8(5, 7, 13, 0.52),
        13.0,
    );
    stroke_line(
        frame,
        base_grip,
        head,
        Color::from_rgba8(142, 130, 112, 0.92),
        9.0,
    );
    stroke_line(
        frame,
        base_grip,
        head,
        with_alpha(theme::ADVISORY, 0.62),
        1.7,
    );

    let angle = (head.y - base_grip.y).atan2(head.x - base_grip.x);
    frame.with_save(|frame| {
        frame.translate(Vector::new(head.x, head.y));
        frame.rotate(angle + std::f32::consts::FRAC_PI_2);

        let shape = polygon(&[
            (-25.0, -10.0),
            (-19.0, -14.0),
            (15.0, -14.0),
            (25.0, -8.0),
            (25.0, 8.0),
            (16.0, 14.0),
            (-19.0, 14.0),
            (-25.0, 10.0),
        ]);
        frame.fill(&shape, theme::SURFACE_HIGH);
        frame.stroke(
            &shape,
            canvas::Stroke::default()
                .with_width(1.5)
                .with_color(with_alpha(theme::CYAN, 0.48 + impact * 0.52)),
        );
        let face = polygon(&[(-25.0, -10.0), (-19.0, -14.0), (-19.0, 14.0), (-25.0, 10.0)]);
        frame.fill(&face, with_alpha(theme::TEXT, 0.26 + impact * 0.56));
        stroke_line(
            frame,
            Point::new(-15.0, -11.0),
            Point::new(15.0, -11.0),
            with_alpha(theme::TEXT, 0.50),
            1.0,
        );
    });
}

fn draw_impact(frame: &mut canvas::Frame, state: ForgeState) {
    let Some(progress) = state.spark_progress else {
        if state.landing > 0.0 {
            let ring = canvas::Path::circle(
                Point::new(BUTTON_CENTER_X, 157.0),
                10.0 + (1.0 - state.landing) * 34.0,
            );
            frame.stroke(
                &ring,
                canvas::Stroke::default()
                    .with_width(1.2)
                    .with_color(with_alpha(theme::DANGER, state.landing * 0.34)),
            );
        }
        return;
    };

    let origin = Point::new(370.0, state.impact_y);
    let power = 1.65;
    let burst = 1.0 + (power - 1.0) * 0.82;
    let fade = (1.0 - progress).powi(2);
    if state.impact > 0.0 {
        let flash = state.impact * (power * 0.72_f32).min(1.0);
        for (radius, color, alpha) in [
            (24.0 * power, theme::CYAN, flash * 0.050),
            (17.0 * power, theme::PROOF, flash * 0.105),
            (9.0 * power, theme::TEXT, flash * 0.18),
            (3.2 * power, theme::TEXT, flash * 0.64),
        ] {
            let glow = canvas::Path::circle(origin, radius);
            frame.fill(&glow, with_alpha(color, alpha));
        }
    }

    let ring = canvas::Path::circle(origin, 8.0 + progress * 46.0 * burst);
    frame.stroke(
        &ring,
        canvas::Stroke::default()
            .with_width(1.2 + (power - 1.0) * 0.7)
            .with_color(with_alpha(theme::CYAN, 0.38 * fade * power.min(1.35))),
    );

    for index in 0..24 {
        let angle = (188.0 + index as f32 * 8.0).to_radians();
        let speed = 36.0 + ((index * 29) % 54) as f32;
        let distance = speed * progress * burst;
        let gravity = 38.0 * progress * progress * (1.0 + (power - 1.0) * 0.25);
        let tail = 9.0 * burst;
        let point = Point::new(
            origin.x + angle.cos() * distance,
            origin.y + angle.sin() * distance + gravity,
        );
        let previous = Point::new(
            origin.x + angle.cos() * (distance - tail).max(0.0),
            origin.y + angle.sin() * (distance - tail).max(0.0) + gravity * 0.78,
        );
        let color = match index % 3 {
            0 => theme::PROOF,
            1 => theme::CYAN,
            _ => theme::ACCENT,
        };
        stroke_line(
            frame,
            previous,
            point,
            with_alpha(color, fade * 0.96),
            (if index % 6 == 0 { 2.2 } else { 1.3 }) * power.min(1.25),
        );
        let spark = canvas::Path::circle(
            point,
            (if index % 6 == 0 { 2.0 } else { 1.1 }) * power.min(1.2),
        );
        frame.fill(&spark, with_alpha(color, fade));
    }
}

fn fill_ellipse(frame: &mut canvas::Frame, center: Point, radii: Vector, color: Color) {
    frame.fill(&ellipse_path(center, radii), color);
}

fn soft_ellipse_glow(
    frame: &mut canvas::Frame,
    center: Point,
    radii: Vector,
    color: Color,
    intensity: f32,
) {
    const LAYERS: usize = 20;
    for layer in 0..LAYERS {
        let progress = layer as f32 / (LAYERS - 1) as f32;
        let scale = 1.0 - progress * 0.84;
        let alpha = intensity * (0.012 + progress * 0.038);
        fill_ellipse(
            frame,
            center,
            Vector::new(radii.x * scale, radii.y * scale),
            with_alpha(color, alpha),
        );
    }
}

fn soft_ellipse_glow_overlay(
    frame: &mut canvas::Frame,
    center: Point,
    radii: Vector,
    color: Color,
    base_intensity: f32,
    total_intensity: f32,
) {
    const LAYERS: usize = 20;
    for layer in 0..LAYERS {
        let progress = layer as f32 / (LAYERS - 1) as f32;
        let scale = 1.0 - progress * 0.84;
        let alpha_factor = 0.012 + progress * 0.038;
        let base_alpha = (base_intensity * alpha_factor).clamp(0.0, 1.0);
        let total_alpha = (total_intensity * alpha_factor).clamp(0.0, 1.0);
        // Preserve the original source-over result after moving the base glow
        // into a cache: base + this overlay must equal the former total alpha.
        let overlay_alpha = if base_alpha >= 1.0 {
            0.0
        } else {
            ((total_alpha - base_alpha) / (1.0 - base_alpha)).clamp(0.0, 1.0)
        };
        fill_ellipse(
            frame,
            center,
            Vector::new(radii.x * scale, radii.y * scale),
            with_alpha(color, overlay_alpha),
        );
    }
}

fn stroke_ellipse(
    frame: &mut canvas::Frame,
    center: Point,
    radii: Vector,
    stroke: canvas::Stroke<'_>,
) {
    frame.stroke(&ellipse_path(center, radii), stroke);
}

fn ellipse_path(center: Point, radii: Vector) -> canvas::Path {
    let radius_x = radii.x.max(0.1);
    let radius_y = radii.y.max(0.1);
    let control_x = radius_x * 0.552_284_8;
    let control_y = radius_y * 0.552_284_8;

    canvas::Path::new(|path| {
        path.move_to(Point::new(center.x + radius_x, center.y));
        path.bezier_curve_to(
            Point::new(center.x + radius_x, center.y + control_y),
            Point::new(center.x + control_x, center.y + radius_y),
            Point::new(center.x, center.y + radius_y),
        );
        path.bezier_curve_to(
            Point::new(center.x - control_x, center.y + radius_y),
            Point::new(center.x - radius_x, center.y + control_y),
            Point::new(center.x - radius_x, center.y),
        );
        path.bezier_curve_to(
            Point::new(center.x - radius_x, center.y - control_y),
            Point::new(center.x - control_x, center.y - radius_y),
            Point::new(center.x, center.y - radius_y),
        );
        path.bezier_curve_to(
            Point::new(center.x + control_x, center.y - radius_y),
            Point::new(center.x + radius_x, center.y - control_y),
            Point::new(center.x + radius_x, center.y),
        );
        path.close();
    })
}

fn stroke_limb(
    frame: &mut canvas::Frame,
    points: &[Point],
    main: Color,
    accent: Color,
    width: f32,
) {
    let path = canvas::Path::new(|path| {
        path.move_to(points[0]);
        for point in &points[1..] {
            path.line_to(*point);
        }
    });
    let rounded = |color, width| {
        canvas::Stroke::default()
            .with_width(width)
            .with_color(color)
            .with_line_cap(canvas::LineCap::Round)
            .with_line_join(canvas::LineJoin::Round)
    };
    frame.stroke(
        &path,
        rounded(Color::from_rgba8(5, 7, 13, 0.60), width + 5.0),
    );
    frame.stroke(&path, rounded(main, width));
    frame.stroke(&path, rounded(accent, 1.4));
}

fn draw_joint(frame: &mut canvas::Frame, point: Point, color: Color) {
    let joint = canvas::Path::circle(point, 4.2);
    frame.fill(&joint, theme::SURFACE_HIGH);
    frame.stroke(
        &joint,
        canvas::Stroke::default()
            .with_width(1.1)
            .with_color(with_alpha(color, 0.75)),
    );
}

fn stroke_line(frame: &mut canvas::Frame, start: Point, end: Point, color: Color, width: f32) {
    let line = canvas::Path::line(start, end);
    frame.stroke(
        &line,
        canvas::Stroke::default()
            .with_width(width)
            .with_color(color)
            .with_line_cap(canvas::LineCap::Round),
    );
}

fn polygon(points: &[(f32, f32)]) -> canvas::Path {
    canvas::Path::new(|path| {
        path.move_to(Point::new(points[0].0, points[0].1));
        for &(x, y) in &points[1..] {
            path.line_to(Point::new(x, y));
        }
        path.close();
    })
}

fn point_lerp(start: Point, end: Point, amount: f32) -> Point {
    Point::new(lerp(start.x, end.x, amount), lerp(start.y, end.y, amount))
}

fn cubic_point(a: Point, b: Point, c: Point, d: Point, amount: f32) -> Point {
    let amount = amount.clamp(0.0, 1.0);
    let inverse = 1.0 - amount;
    Point::new(
        inverse.powi(3) * a.x
            + 3.0 * inverse.powi(2) * amount * b.x
            + 3.0 * inverse * amount.powi(2) * c.x
            + amount.powi(3) * d.x,
        inverse.powi(3) * a.y
            + 3.0 * inverse.powi(2) * amount * b.y
            + 3.0 * inverse * amount.powi(2) * c.y
            + amount.powi(3) * d.y,
    )
}

fn elbow_between(shoulder: Point, hand: Point, bend: f32) -> Point {
    let dx = hand.x - shoulder.x;
    let dy = hand.y - shoulder.y;
    let length = dx.hypot(dy).max(1.0);
    Point::new(
        (shoulder.x + hand.x) * 0.5 - dy / length * bend,
        (shoulder.y + hand.y) * 0.5 + dx / length * bend,
    )
}

fn smoothstep(value: f32) -> f32 {
    let value = value.clamp(0.0, 1.0);
    value * value * (3.0 - 2.0 * value)
}

fn ease_out(value: f32) -> f32 {
    1.0 - (1.0 - value.clamp(0.0, 1.0)).powi(3)
}

fn lerp(start: f32, end: f32, amount: f32) -> f32 {
    start + (end - start) * amount.clamp(0.0, 1.0)
}

fn with_alpha(color: Color, alpha: f32) -> Color {
    Color {
        a: color.a * alpha.clamp(0.0, 1.0),
        ..color
    }
}

fn mix_color(from: Color, to: Color, amount: f32) -> Color {
    let amount = amount.clamp(0.0, 1.0);
    Color {
        r: lerp(from.r, to.r, amount),
        g: lerp(from.g, to.g, amount),
        b: lerp(from.b, to.b, amount),
        a: lerp(from.a, to.a, amount),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intro_enters_from_the_right_and_reaches_the_forge() {
        assert!(forge_state(0.0).body_x > DESIGN_WIDTH);
        let ready = forge_state(INTRO_END - 0.01);
        assert!(ready.body_x < 490.0);
        assert!(ready.prepare > 0.95);
    }

    #[test]
    fn forge_loop_strikes_then_drops_blocks_and_reacts() {
        let strike = forge_state(INTRO_END + STRIKE_DURATION * 0.55);
        assert!(strike.impact > 0.95);

        let falling = forge_state(INTRO_END + (DROP_START + DROP_END) * 0.5);
        assert!(falling.drop_progress.is_some());

        let surprised = forge_state(INTRO_END + 5.35);
        assert!(surprised.surprise > 0.95);

        let repeated = forge_state(INTRO_END + FORGE_CYCLE + STRIKE_DURATION * 0.55);
        assert!(repeated.impact > 0.95);
    }

    #[test]
    fn each_block_generation_uses_a_new_complete_color_order() {
        for generation in 0..6 {
            let colors = block_color_palette(generation);
            assert!(colors.contains(&theme::CYAN));
            assert!(colors.contains(&theme::ACCENT));
            assert!(colors.contains(&theme::DANGER));
            assert_ne!(colors, block_color_palette(generation + 1));
        }
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use iced::border::Radius;
use iced::widget::{
    button as button_widget, container, overlay::menu, pick_list, scrollable as scrollable_widget,
    text_editor as editor_widget, text_input as input_widget, toggler,
};
use iced::{
    font, gradient, theme::Palette, Background, Border, Color, Font, Radians, Shadow, Theme, Vector,
};

pub const BACKGROUND: Color = Color::from_rgb8(10, 12, 20);
pub const SURFACE: Color = Color::from_rgba8(39, 42, 58, 0.84);
pub const SURFACE_ALT: Color = Color::from_rgba8(50, 54, 72, 0.88);
pub const SURFACE_HIGH: Color = Color::from_rgba8(63, 68, 88, 0.93);
pub const LINE: Color = Color::from_rgba8(214, 224, 255, 0.14);
pub const LINE_STRONG: Color = Color::from_rgba8(224, 232, 255, 0.25);
pub const TEXT: Color = Color::from_rgb8(246, 247, 250);
pub const MUTED: Color = Color::from_rgb8(195, 198, 211);
pub const DIM: Color = Color::from_rgb8(132, 135, 153);
pub const ACCENT: Color = Color::from_rgb8(52, 224, 111);
pub const CYAN: Color = Color::from_rgb8(103, 215, 246);
pub const PROOF: Color = Color::from_rgb8(206, 88, 214);
pub const WARNING: Color = Color::from_rgb8(231, 218, 61);
pub const ADVISORY: Color = Color::from_rgb8(255, 176, 74);
pub const DANGER: Color = Color::from_rgb8(255, 107, 119);
pub const INK: Color = Color::from_rgb8(31, 33, 43);
pub const CHROME: Color = Color::from_rgba8(34, 37, 50, 0.86);
pub const TECH_FONT: Font = Font {
    family: font::Family::Name("Noto Sans Mono"),
    weight: font::Weight::Normal,
    stretch: font::Stretch::Normal,
    style: font::Style::Normal,
};
pub const BRAND_FONT: Font = Font {
    family: font::Family::Name("Noto Sans"),
    weight: font::Weight::Bold,
    stretch: font::Stretch::Normal,
    style: font::Style::Normal,
};
pub const BRAND_REGULAR_FONT: Font = Font {
    family: font::Family::Name("Noto Sans"),
    weight: font::Weight::Normal,
    stretch: font::Stretch::Normal,
    style: font::Style::Normal,
};
pub const SYMBOL_FONT: Font = Font {
    family: font::Family::Name("Noto Sans Symbols"),
    weight: font::Weight::Bold,
    stretch: font::Stretch::Normal,
    style: font::Style::Normal,
};
pub const CJK_FONT: Font = Font {
    family: font::Family::Name("Noto Sans CJK SC"),
    weight: font::Weight::Normal,
    stretch: font::Stretch::Normal,
    style: font::Style::Normal,
};

fn soft_shadow() -> Shadow {
    Shadow {
        color: Color::from_rgba8(5, 7, 13, 0.20),
        offset: Vector::new(0.0, 2.0),
        blur_radius: 6.0,
    }
}

pub fn paranoid_theme() -> Theme {
    Theme::custom(
        "ParanO(1)d System",
        Palette {
            background: BACKGROUND,
            text: TEXT,
            primary: ACCENT,
            success: ACCENT,
            warning: WARNING,
            danger: DANGER,
        },
    )
}

pub fn root(_: &Theme) -> container::Style {
    container::Style::default()
        .background(
            gradient::Linear::new(Radians(0.0))
                .add_stop(0.0, Color::from_rgb8(7, 9, 15))
                .add_stop(0.48, Color::from_rgb8(14, 17, 27))
                .add_stop(1.0, Color::from_rgb8(10, 12, 20)),
        )
        .color(TEXT)
}

pub fn language_background(_: &Theme) -> container::Style {
    container::Style::default()
        .background(
            gradient::Linear::new(Radians(0.0))
                .add_stop(0.0, Color::from_rgb8(7, 9, 15))
                .add_stop(0.48, Color::from_rgb8(14, 17, 27))
                .add_stop(1.0, Color::from_rgb8(10, 12, 20)),
        )
        .color(TEXT)
}

pub fn surface(_: &Theme) -> container::Style {
    container::Style {
        text_color: Some(TEXT),
        background: Some(Background::Color(SURFACE)),
        border: Border {
            color: LINE,
            width: 1.0,
            radius: Radius::from(8.0),
        },
        shadow: soft_shadow(),
        snap: true,
    }
}

pub fn surface_alt(_: &Theme) -> container::Style {
    container::Style {
        text_color: Some(TEXT),
        background: Some(Background::Color(SURFACE_ALT)),
        border: Border {
            color: LINE,
            width: 1.0,
            radius: Radius::from(6.0),
        },
        shadow: Shadow::default(),
        snap: true,
    }
}

pub fn node_log_panel(_: &Theme) -> container::Style {
    container::Style {
        text_color: Some(TEXT),
        background: Some(Background::Color(SURFACE)),
        border: Border {
            color: Color { a: 0.42, ..CYAN },
            width: 1.0,
            radius: Radius::from(8.0),
        },
        shadow: soft_shadow(),
        snap: true,
    }
}

pub fn top_bar(_: &Theme) -> container::Style {
    container::Style {
        text_color: Some(TEXT),
        background: Some(Background::Gradient(
            gradient::Linear::new(Radians(0.0))
                .add_stop(0.0, Color::from_rgba8(24, 27, 39, 0.62))
                .add_stop(0.46, Color::from_rgba8(39, 43, 58, 0.72))
                .add_stop(1.0, Color::from_rgba8(53, 57, 72, 0.66))
                .into(),
        )),
        border: Border {
            color: Color::from_rgba8(230, 237, 255, 0.20),
            width: 1.0,
            radius: Radius::from(10.0),
        },
        shadow: Shadow {
            color: Color::from_rgba8(1, 2, 7, 0.48),
            offset: Vector::new(0.0, 5.0),
            blur_radius: 13.0,
        },
        snap: true,
    }
}

pub fn command_bar(_: &Theme) -> container::Style {
    container::Style {
        text_color: Some(TEXT),
        background: Some(Background::Color(CHROME)),
        border: Border {
            color: LINE_STRONG,
            width: 1.0,
            radius: Radius::from(8.0),
        },
        shadow: soft_shadow(),
        snap: true,
    }
}

pub fn status_panel(_: &Theme) -> container::Style {
    container::Style {
        text_color: Some(TEXT),
        background: Some(Background::Color(CHROME)),
        border: Border {
            color: Color::from_rgba8(103, 215, 246, 0.18),
            width: 1.0,
            radius: Radius::from(8.0),
        },
        shadow: Shadow::default(),
        snap: true,
    }
}

pub fn secret_visual(_: &Theme) -> container::Style {
    container::Style {
        text_color: Some(TEXT),
        background: Some(Background::Color(Color::from_rgba8(28, 31, 43, 0.88))),
        border: Border {
            color: Color::from_rgba8(206, 88, 214, 0.32),
            width: 1.0,
            radius: Radius::from(8.0),
        },
        shadow: soft_shadow(),
        snap: true,
    }
}

pub fn secret_key_token(_: &Theme) -> container::Style {
    container::Style {
        text_color: Some(TEXT),
        background: Some(Background::Color(Color::from_rgb8(34, 38, 49))),
        border: Border {
            color: Color::from_rgba8(52, 224, 111, 0.58),
            width: 1.0,
            radius: Radius::from(10.0),
        },
        shadow: Shadow {
            color: Color::from_rgba8(3, 5, 10, 0.48),
            offset: Vector::new(0.0, 5.0),
            blur_radius: 13.0,
        },
        snap: true,
    }
}

pub fn secret_address_token(depth: u8) -> container::Style {
    let lift = 3.0 - f32::from(depth).min(2.0) * 0.7;
    container::Style {
        text_color: Some(TEXT),
        background: Some(Background::Color(Color::from_rgb8(
            48 + depth.min(2) * 2,
            51 + depth.min(2) * 2,
            68 + depth.min(2) * 2,
        ))),
        border: Border {
            color: Color::from_rgba8(103, 215, 246, 0.28),
            width: 1.0,
            radius: Radius::from(5.0),
        },
        shadow: Shadow {
            color: Color::from_rgba8(3, 5, 10, 0.42),
            offset: Vector::new(0.0, lift),
            blur_radius: 6.0,
        },
        snap: true,
    }
}

pub fn photo_frame(_: &Theme) -> container::Style {
    container::Style {
        text_color: Some(TEXT),
        background: Some(Background::Color(Color::from_rgb8(22, 25, 34))),
        border: Border {
            color: Color::from_rgba8(103, 215, 246, 0.42),
            width: 1.0,
            radius: Radius::from(6.0),
        },
        shadow: Shadow::default(),
        snap: true,
    }
}

pub fn status_capsule(_: &Theme) -> container::Style {
    container::Style {
        text_color: Some(TEXT),
        background: Some(Background::Color(SURFACE)),
        border: Border {
            color: LINE,
            width: 1.0,
            radius: Radius::from(6.0),
        },
        shadow: Shadow::default(),
        snap: true,
    }
}

pub fn external_data_switch(_: &Theme, status: toggler::Status) -> toggler::Style {
    let (enabled, hovered, disabled) = match status {
        toggler::Status::Active { is_toggled } => (is_toggled, false, false),
        toggler::Status::Hovered { is_toggled } => (is_toggled, true, false),
        toggler::Status::Disabled { is_toggled } => (is_toggled, false, true),
    };
    let (top, bottom) = if disabled {
        (Color::from_rgb8(36, 40, 52), Color::from_rgb8(29, 32, 43))
    } else if enabled {
        (
            Color::from_rgb8(52, 209, 105),
            Color::from_rgb8(25, 144, 72),
        )
    } else {
        (Color::from_rgb8(22, 26, 37), Color::from_rgb8(44, 49, 65))
    };
    let edge = if disabled {
        LINE
    } else if enabled {
        Color { a: 0.8, ..ACCENT }
    } else if hovered {
        Color { a: 0.6, ..CYAN }
    } else {
        Color::from_rgba8(188, 204, 231, 0.3)
    };
    let knob_top = if disabled { DIM } else { TEXT };
    let knob_bottom = if disabled {
        Color::from_rgb8(106, 112, 129)
    } else if hovered {
        Color::from_rgb8(221, 238, 241)
    } else {
        Color::from_rgb8(178, 192, 207)
    };
    toggler::Style {
        background: gradient::Linear::new(Radians(0.0))
            .add_stop(0.0, top)
            .add_stop(1.0, bottom)
            .into(),
        background_border_width: 1.0,
        background_border_color: edge,
        foreground: gradient::Linear::new(Radians(0.0))
            .add_stop(0.0, knob_top)
            .add_stop(1.0, knob_bottom)
            .into(),
        foreground_border_width: 1.0,
        foreground_border_color: Color::from_rgba8(250, 255, 255, 0.42),
        text_color: Some(if disabled { DIM } else { MUTED }),
        border_radius: None,
        padding_ratio: 3.0 / 22.0,
    }
}

pub fn state_scale_tick(active: bool) -> impl Fn(&Theme) -> container::Style {
    move |_| {
        container::Style::default().background(if active {
            ACCENT
        } else {
            Color::from_rgba8(214, 224, 255, 0.12)
        })
    }
}

fn title_style(background: Color) -> container::Style {
    container::Style {
        text_color: Some(INK),
        background: Some(Background::Color(background)),
        border: Border {
            color: Color::TRANSPARENT,
            width: 0.0,
            radius: Radius::from(4.0),
        },
        shadow: Shadow::default(),
        snap: true,
    }
}

pub fn title_bar_cyan(_: &Theme) -> container::Style {
    title_style(CYAN)
}

pub fn title_bar_proof(_: &Theme) -> container::Style {
    title_style(PROOF)
}

pub fn title_bar_accent(_: &Theme) -> container::Style {
    title_style(ACCENT)
}

pub fn table_header(_: &Theme) -> container::Style {
    container::Style {
        border: Border {
            radius: Radius::from(3.0),
            ..Border::default()
        },
        ..title_style(ACCENT)
    }
}

pub fn utxo_table_header(_: &Theme) -> container::Style {
    container::Style {
        text_color: Some(MUTED),
        background: Some(Background::Color(SURFACE_ALT)),
        border: Border {
            color: Color { a: 0.50, ..CYAN },
            width: 1.0,
            radius: Radius::from(3.0),
        },
        shadow: Shadow::default(),
        snap: true,
    }
}

pub fn scope_table_header(_: &Theme) -> container::Style {
    container::Style {
        text_color: Some(MUTED),
        background: Some(Background::Color(SURFACE_ALT)),
        border: Border {
            color: Color::from_rgba8(206, 88, 214, 0.34),
            width: 1.0,
            radius: Radius::from(3.0),
        },
        shadow: Shadow::default(),
        snap: true,
    }
}

pub fn table_row(alternate: bool) -> impl Fn(&Theme) -> container::Style {
    move |_| {
        container::Style::default()
            .background(if alternate { SURFACE_ALT } else { SURFACE })
            .color(TEXT)
    }
}

pub fn transaction_row(alternate: bool, status: button_widget::Status) -> button_widget::Style {
    let hovered = matches!(
        status,
        button_widget::Status::Hovered | button_widget::Status::Pressed
    );
    button_widget::Style {
        background: Some(Background::Color(if hovered {
            SURFACE_HIGH
        } else if alternate {
            SURFACE_ALT
        } else {
            SURFACE
        })),
        text_color: TEXT,
        border: Border {
            color: if hovered {
                LINE_STRONG
            } else {
                Color::TRANSPARENT
            },
            width: if hovered { 1.0 } else { 0.0 },
            radius: Radius::from(2.0),
        },
        shadow: Shadow::default(),
        snap: true,
    }
}

pub fn utxo_row(
    alternate: bool,
    selected: bool,
    status: button_widget::Status,
) -> button_widget::Style {
    let hovered = matches!(
        status,
        button_widget::Status::Hovered | button_widget::Status::Pressed
    );
    let background = if selected {
        Color::from_rgba8(206, 88, 214, if hovered { 0.19 } else { 0.12 })
    } else if hovered {
        SURFACE_HIGH
    } else if alternate {
        SURFACE_ALT
    } else {
        SURFACE
    };

    button_widget::Style {
        background: Some(Background::Color(background)),
        text_color: TEXT,
        border: Border {
            color: if selected { PROOF } else { Color::TRANSPARENT },
            width: if selected { 1.0 } else { 0.0 },
            radius: Radius::from(2.0),
        },
        shadow: Shadow::default(),
        snap: true,
    }
}

pub fn divider(_: &Theme) -> container::Style {
    container::Style::default().background(LINE)
}

pub fn market_card(status: button_widget::Status) -> button_widget::Style {
    let hovered = matches!(
        status,
        button_widget::Status::Hovered | button_widget::Status::Pressed
    );
    button_widget::Style {
        background: Some(raised_gradient(if hovered {
            SURFACE_HIGH
        } else {
            SURFACE_ALT
        })),
        text_color: TEXT,
        border: Border {
            color: if hovered {
                Color { a: 0.6, ..CYAN }
            } else {
                LINE
            },
            width: 1.0,
            radius: Radius::from(8.0),
        },
        shadow: neutral_button_shadow(status, hovered),
        snap: true,
    }
}

pub fn scrollable(theme: &Theme, status: scrollable_widget::Status) -> scrollable_widget::Style {
    let mut style = scrollable_widget::default(theme, status);
    let active = matches!(
        status,
        scrollable_widget::Status::Hovered {
            is_vertical_scrollbar_hovered: true,
            ..
        } | scrollable_widget::Status::Dragged {
            is_vertical_scrollbar_dragged: true,
            ..
        }
    );

    style.vertical_rail.background = Some(Background::Color(Color::from_rgba8(
        103,
        215,
        246,
        if active { 0.10 } else { 0.05 },
    )));
    style.vertical_rail.border = Border {
        color: Color::TRANSPARENT,
        width: 0.0,
        radius: Radius::from(99.0),
    };
    style.vertical_rail.scroller.background = Background::Color(Color {
        a: if active { 0.92 } else { 0.48 },
        ..CYAN
    });
    style.vertical_rail.scroller.border = Border {
        color: Color::TRANSPARENT,
        width: 0.0,
        radius: Radius::from(99.0),
    };
    style
}

pub fn status_dot(color: Color) -> impl Fn(&Theme) -> container::Style {
    move |_| {
        container::Style::default()
            .background(color)
            .border(Border {
                color,
                width: 0.0,
                radius: Radius::from(99.0),
            })
    }
}

pub fn advisory_badge(_: &Theme) -> container::Style {
    container::Style {
        text_color: Some(ADVISORY),
        background: Some(Background::Color(Color {
            a: 0.18,
            ..ADVISORY
        })),
        border: Border {
            color: Color {
                a: 0.76,
                ..ADVISORY
            },
            width: 1.25,
            radius: Radius::from(99.0),
        },
        shadow: Shadow::default(),
        snap: true,
    }
}

pub fn advisory_card(_: &Theme) -> container::Style {
    container::Style {
        text_color: Some(TEXT),
        background: Some(Background::Color(CHROME)),
        border: Border {
            color: Color {
                a: 0.68,
                ..ADVISORY
            },
            width: 1.0,
            radius: Radius::from(8.0),
        },
        shadow: soft_shadow(),
        snap: true,
    }
}

pub fn overlay(_: &Theme) -> container::Style {
    container::Style::default().background(Color::from_rgba8(12, 13, 19, 0.78))
}

pub fn proof_forge_overlay(_: &Theme) -> container::Style {
    container::Style {
        text_color: Some(TEXT),
        background: Some(Background::Color(Color::from_rgba8(18, 20, 29, 0.97))),
        border: Border {
            color: Color::from_rgba8(206, 88, 214, 0.42),
            width: 1.0,
            radius: Radius::from(8.0),
        },
        shadow: Shadow {
            color: Color::from_rgba8(206, 88, 214, 0.16),
            offset: Vector::new(0.0, 0.0),
            blur_radius: 14.0,
        },
        snap: true,
    }
}

pub fn shutdown_forge_overlay(_: &Theme) -> container::Style {
    container::Style {
        text_color: Some(TEXT),
        background: Some(Background::Color(Color::from_rgba8(12, 13, 19, 0.94))),
        border: Border {
            color: Color::from_rgba8(206, 88, 214, 0.34),
            width: 1.0,
            radius: Radius::from(0.0),
        },
        shadow: Shadow::default(),
        snap: true,
    }
}

pub fn key_cap(color: Color) -> impl Fn(&Theme) -> container::Style {
    move |_| container::Style {
        text_color: Some(INK),
        background: Some(Background::Color(color)),
        border: Border {
            color: Color::from_rgba8(228, 250, 255, 0.28),
            width: 1.0,
            radius: Radius::from(3.0),
        },
        shadow: Shadow::default(),
        snap: true,
    }
}

pub fn text_input(_: &Theme, status: input_widget::Status) -> input_widget::Style {
    let focused = matches!(status, input_widget::Status::Focused { .. });
    let hovered = matches!(status, input_widget::Status::Hovered);

    input_widget::Style {
        background: Background::Color(SURFACE),
        border: Border {
            color: if focused {
                CYAN
            } else if hovered {
                LINE_STRONG
            } else {
                LINE
            },
            width: 1.0,
            radius: Radius::from(6.0),
        },
        icon: MUTED,
        placeholder: DIM,
        value: TEXT,
        selection: Color::from_rgba8(103, 215, 246, 0.28),
    }
}

pub fn scope_search_input(_: &Theme, status: input_widget::Status) -> input_widget::Style {
    let focused = matches!(status, input_widget::Status::Focused { .. });
    let hovered = matches!(status, input_widget::Status::Hovered);

    input_widget::Style {
        background: Background::Color(SURFACE),
        border: Border {
            color: Color {
                a: if focused {
                    1.0
                } else if hovered {
                    0.82
                } else {
                    0.64
                },
                ..ACCENT
            },
            width: if focused { 2.0 } else { 1.5 },
            radius: Radius::from(6.0),
        },
        icon: ACCENT,
        placeholder: MUTED,
        value: TEXT,
        selection: Color::from_rgba8(52, 224, 111, 0.28),
    }
}

pub fn text_editor(_: &Theme, status: editor_widget::Status) -> editor_widget::Style {
    let focused = matches!(status, editor_widget::Status::Focused { .. });
    let hovered = matches!(status, editor_widget::Status::Hovered);

    editor_widget::Style {
        background: Background::Color(SURFACE),
        border: Border {
            color: if focused {
                CYAN
            } else if hovered {
                LINE_STRONG
            } else {
                LINE
            },
            width: 1.0,
            radius: Radius::from(6.0),
        },
        placeholder: DIM,
        value: TEXT,
        selection: Color::from_rgba8(103, 215, 246, 0.28),
    }
}

pub fn node_log_editor(_: &Theme, status: editor_widget::Status) -> editor_widget::Style {
    let focused = matches!(status, editor_widget::Status::Focused { .. });
    let hovered = matches!(status, editor_widget::Status::Hovered);

    editor_widget::Style {
        background: Background::Color(Color::from_rgb8(18, 20, 27)),
        border: Border {
            color: if focused {
                ACCENT
            } else if hovered {
                Color { a: 0.72, ..CYAN }
            } else {
                Color { a: 0.34, ..CYAN }
            },
            width: if focused { 1.5 } else { 1.0 },
            radius: Radius::from(5.0),
        },
        placeholder: DIM,
        value: Color::from_rgb8(196, 228, 207),
        selection: Color::from_rgba8(103, 215, 246, 0.32),
    }
}

pub fn selectable_address(_: &Theme, _: input_widget::Status) -> input_widget::Style {
    input_widget::Style {
        background: Background::Color(Color::TRANSPARENT),
        border: Border::default(),
        icon: MUTED,
        placeholder: DIM,
        value: TEXT,
        selection: Color::from_rgba8(103, 215, 246, 0.34),
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ButtonKind {
    Primary,
    Secondary,
    Ghost,
    Command,
    CommandActive,
}

fn primary_button_shadow(status: button_widget::Status) -> Shadow {
    if matches!(status, button_widget::Status::Pressed) {
        Shadow {
            color: Color::from_rgba8(1, 2, 6, 0.44),
            offset: Vector::new(0.0, 1.5),
            blur_radius: 3.0,
        }
    } else {
        Shadow {
            color: Color::from_rgba8(1, 2, 6, 0.58),
            offset: Vector::new(0.0, 4.0),
            blur_radius: 8.0,
        }
    }
}

pub fn colored_primary(color: Color, status: button_widget::Status) -> button_widget::Style {
    if matches!(status, button_widget::Status::Disabled) {
        return disabled_button_style();
    }

    let hovered = matches!(
        status,
        button_widget::Status::Hovered | button_widget::Status::Pressed
    );
    let pressed = matches!(status, button_widget::Status::Pressed);
    let base = if pressed {
        shade(color, 0.16)
    } else if hovered {
        tint(color, 0.10)
    } else {
        color
    };

    button_widget::Style {
        background: Some(raised_gradient(base)),
        text_color: INK,
        border: Border {
            color: Color {
                a: 0.38,
                ..tint(color, 0.68)
            },
            width: if pressed { 1.0 } else { 1.15 },
            radius: Radius::from(6.0),
        },
        shadow: primary_button_shadow(status),
        snap: true,
    }
}

/// The first-run language controls use the ordinary primary-button language,
/// with a firmer contact shadow to match the forged blocks above them.
pub fn language_choice(color: Color, status: button_widget::Status) -> button_widget::Style {
    let mut style = colored_primary(color, status);
    let pressed = matches!(status, button_widget::Status::Pressed);
    style.shadow = Shadow {
        color: Color::from_rgba8(1, 2, 6, if pressed { 0.44 } else { 0.72 }),
        offset: Vector::new(0.0, if pressed { 2.0 } else { 7.0 }),
        blur_radius: if pressed { 3.0 } else { 12.0 },
    };
    style.border.width = if pressed { 1.0 } else { 1.25 };
    style
}

fn raised_gradient(color: Color) -> Background {
    Background::Gradient(
        gradient::Linear::new(Radians(0.0))
            .add_stop(0.0, shade(color, 0.17))
            .add_stop(0.42, color)
            .add_stop(1.0, tint(color, 0.18))
            .into(),
    )
}

fn tint(color: Color, amount: f32) -> Color {
    Color {
        r: color.r + (1.0 - color.r) * amount,
        g: color.g + (1.0 - color.g) * amount,
        b: color.b + (1.0 - color.b) * amount,
        ..color
    }
}

fn shade(color: Color, amount: f32) -> Color {
    Color {
        r: color.r * (1.0 - amount),
        g: color.g * (1.0 - amount),
        b: color.b * (1.0 - amount),
        ..color
    }
}

fn disabled_button_style() -> button_widget::Style {
    button_widget::Style {
        background: Some(raised_gradient(Color::from_rgba8(38, 42, 55, 0.72))),
        text_color: DIM,
        border: Border {
            color: Color::from_rgba8(214, 224, 255, 0.09),
            width: 1.0,
            radius: Radius::from(6.0),
        },
        shadow: Shadow {
            color: Color::from_rgba8(1, 2, 6, 0.18),
            offset: Vector::new(0.0, 2.0),
            blur_radius: 4.0,
        },
        snap: true,
    }
}

fn neutral_button_shadow(status: button_widget::Status, visible: bool) -> Shadow {
    let pressed = matches!(status, button_widget::Status::Pressed);
    if !visible && !pressed {
        return Shadow::default();
    }

    Shadow {
        color: Color::from_rgba8(1, 2, 6, if pressed { 0.30 } else { 0.40 }),
        offset: Vector::new(0.0, if pressed { 1.0 } else { 3.0 }),
        blur_radius: if pressed { 2.0 } else { 7.0 },
    }
}

pub fn asset_picker(status: pick_list::Status) -> pick_list::Style {
    let opened = matches!(status, pick_list::Status::Opened { .. });
    let hovered = matches!(status, pick_list::Status::Hovered);
    let base = if opened {
        Color::from_rgb8(29, 36, 49)
    } else if hovered {
        Color::from_rgb8(45, 53, 70)
    } else {
        Color::from_rgb8(38, 42, 57)
    };

    pick_list::Style {
        text_color: TEXT,
        placeholder_color: DIM,
        handle_color: if opened || hovered { CYAN } else { MUTED },
        background: raised_gradient(base),
        border: Border {
            color: if opened {
                Color { a: 0.72, ..CYAN }
            } else if hovered {
                Color { a: 0.46, ..CYAN }
            } else {
                Color::from_rgba8(214, 224, 255, 0.28)
            },
            width: 1.0,
            radius: Radius::from(7.0),
        },
    }
}

pub fn asset_picker_frame() -> container::Style {
    container::Style {
        border: Border {
            radius: Radius::from(7.0),
            ..Border::default()
        },
        shadow: Shadow {
            color: Color::from_rgba8(1, 2, 6, 0.46),
            offset: Vector::new(0.0, 3.0),
            blur_radius: 7.0,
        },
        ..container::Style::default()
    }
}

pub fn asset_picker_menu() -> menu::Style {
    menu::Style {
        background: raised_gradient(Color::from_rgb8(28, 32, 45)),
        border: Border {
            color: Color::from_rgba8(165, 195, 221, 0.40),
            width: 1.0,
            radius: Radius::from(7.0),
        },
        text_color: MUTED,
        selected_text_color: TEXT,
        selected_background: raised_gradient(Color::from_rgb8(38, 65, 76)),
        shadow: Shadow {
            color: Color::from_rgba8(1, 2, 6, 0.68),
            offset: Vector::new(0.0, 8.0),
            blur_radius: 18.0,
        },
    }
}

pub fn asset_picker_locked() -> container::Style {
    let style = asset_picker(pick_list::Status::Active);
    container::Style {
        text_color: Some(DIM),
        background: Some(style.background),
        border: Border {
            color: Color::from_rgba8(214, 224, 255, 0.14),
            ..style.border
        },
        ..asset_picker_frame()
    }
}

pub fn button(kind: ButtonKind, status: button_widget::Status) -> button_widget::Style {
    if matches!(status, button_widget::Status::Disabled) {
        return disabled_button_style();
    }

    let hovered = matches!(
        status,
        button_widget::Status::Hovered | button_widget::Status::Pressed
    );
    let pressed = matches!(status, button_widget::Status::Pressed);

    match kind {
        ButtonKind::Primary => colored_primary(ACCENT, status),
        ButtonKind::Secondary => {
            let base = if pressed {
                shade(SURFACE_ALT, 0.14)
            } else if hovered {
                tint(SURFACE_HIGH, 0.06)
            } else {
                SURFACE_ALT
            };
            button_widget::Style {
                background: Some(raised_gradient(base)),
                text_color: TEXT,
                border: Border {
                    color: if hovered {
                        Color {
                            a: 0.42,
                            ..LINE_STRONG
                        }
                    } else {
                        Color { a: 0.22, ..LINE }
                    },
                    width: 1.0,
                    radius: Radius::from(6.0),
                },
                shadow: neutral_button_shadow(status, true),
                snap: true,
            }
        }
        ButtonKind::Ghost => {
            let base = if pressed {
                Color::from_rgba8(44, 49, 65, 0.82)
            } else if hovered {
                Color::from_rgba8(55, 61, 80, 0.74)
            } else {
                Color::from_rgba8(34, 38, 51, 0.30)
            };
            button_widget::Style {
                background: Some(raised_gradient(base)),
                text_color: if hovered { TEXT } else { MUTED },
                border: Border {
                    color: if hovered {
                        Color::from_rgba8(224, 232, 255, 0.22)
                    } else {
                        Color::from_rgba8(214, 224, 255, 0.07)
                    },
                    width: 1.0,
                    radius: Radius::from(5.0),
                },
                shadow: neutral_button_shadow(status, hovered),
                snap: true,
            }
        }
        ButtonKind::Command => {
            let base = if pressed {
                Color::from_rgba8(58, 116, 137, 0.34)
            } else if hovered {
                Color::from_rgba8(46, 86, 108, 0.30)
            } else {
                Color::from_rgba8(34, 38, 51, 0.18)
            };
            button_widget::Style {
                background: Some(raised_gradient(base)),
                text_color: TEXT,
                border: Border {
                    color: if hovered {
                        Color::from_rgba8(103, 215, 246, 0.22)
                    } else {
                        Color::from_rgba8(214, 224, 255, 0.05)
                    },
                    width: 1.0,
                    radius: Radius::from(5.0),
                },
                shadow: neutral_button_shadow(status, hovered),
                snap: true,
            }
        }
        ButtonKind::CommandActive => {
            let base = if pressed {
                Color::from_rgba8(50, 132, 158, 0.46)
            } else if hovered {
                Color::from_rgba8(51, 119, 145, 0.42)
            } else {
                Color::from_rgba8(43, 91, 113, 0.38)
            };
            button_widget::Style {
                background: Some(raised_gradient(base)),
                text_color: CYAN,
                border: Border {
                    color: Color::from_rgba8(103, 215, 246, 0.38),
                    width: 1.0,
                    radius: Radius::from(5.0),
                },
                shadow: neutral_button_shadow(status, true),
                snap: true,
            }
        }
    }
}

pub fn consolidation_button(status: button_widget::Status) -> button_widget::Style {
    if matches!(status, button_widget::Status::Disabled) {
        return button(ButtonKind::Secondary, status);
    }

    let hovered = matches!(
        status,
        button_widget::Status::Hovered | button_widget::Status::Pressed
    );
    let pressed = matches!(status, button_widget::Status::Pressed);

    let base = if pressed {
        Color {
            a: 0.36,
            ..ADVISORY
        }
    } else if hovered {
        Color {
            a: 0.29,
            ..ADVISORY
        }
    } else {
        Color {
            a: 0.20,
            ..ADVISORY
        }
    };

    button_widget::Style {
        background: Some(raised_gradient(base)),
        text_color: ADVISORY,
        border: Border {
            color: Color {
                a: if hovered { 0.95 } else { 0.72 },
                ..ADVISORY
            },
            width: if hovered { 1.5 } else { 1.25 },
            radius: Radius::from(6.0),
        },
        shadow: neutral_button_shadow(status, true),
        snap: true,
    }
}

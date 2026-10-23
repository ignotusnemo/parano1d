// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

mod app;
mod app_icon;
mod assets;
mod backend;
mod contracts;
mod i18n;
mod market_data;
mod model;
mod secret;
mod theme;
mod view;
mod widgets;

use iced::{window, Size};

#[cfg(target_os = "linux")]
const LINUX_APPLICATION_ID: &str = "org.parano1d.wallet";

fn app_theme(_: &app::App) -> iced::Theme {
    theme::paranoid_theme()
}

fn app_title(app: &app::App) -> String {
    if app.snapshot.network.testnet {
        concat!("Parano1d TESTNET ", env!("CARGO_PKG_VERSION")).into()
    } else {
        "Parano1d".into()
    }
}

fn window_settings() -> window::Settings {
    let settings = window::Settings {
        size: Size::new(1200.0, 760.0),
        min_size: Some(Size::new(920.0, 640.0)),
        position: window::Position::Centered,
        icon: Some(app_icon::icon()),
        ..window::Settings::default()
    };
    #[cfg(target_os = "linux")]
    {
        let mut settings = settings;
        settings.platform_specific.application_id = LINUX_APPLICATION_ID.into();
        settings
    }
    #[cfg(not(target_os = "linux"))]
    {
        settings
    }
}

fn handle_process_command() -> bool {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let Some(argument) = arguments.next() else {
        return false;
    };
    if arguments.next().is_some() {
        return false;
    }

    if argument == "--version" || argument == "-V" {
        println!("Parano1d {}", env!("CARGO_PKG_VERSION"));
        return true;
    }
    if argument != "--release-self-check" {
        return false;
    }

    let node = backend::bundled_node_binary();
    match node {
        Some(node) if node.is_file() => {
            println!(
                "Parano1d {} release self-check OK",
                env!("CARGO_PKG_VERSION")
            );
            true
        }
        Some(node) => {
            eprintln!("bundled node is missing: {}", node.display());
            std::process::exit(1);
        }
        None => {
            eprintln!("could not resolve the wallet executable directory");
            std::process::exit(1);
        }
    }
}

fn main() -> iced::Result {
    if handle_process_command() {
        return Ok(());
    }

    iced::application(app::App::new, app::App::update, app::App::view)
        .title(app_title)
        .theme(app_theme)
        .subscription(app::App::subscription)
        .font(include_bytes!("../assets/fonts/NotoSansMono-Regular.ttf").as_slice())
        .font(include_bytes!("../assets/fonts/NotoSans-Regular.ttf").as_slice())
        .font(include_bytes!("../assets/fonts/NotoSans-Bold.ttf").as_slice())
        .font(include_bytes!("../assets/fonts/NotoSansSymbols-Bold.ttf").as_slice())
        .font(include_bytes!("../assets/fonts/NotoSansCJKsc-UI.otf").as_slice())
        .default_font(theme::TECH_FONT)
        .window(window_settings())
        .exit_on_close_request(false)
        .antialiasing(true)
        .run()
}

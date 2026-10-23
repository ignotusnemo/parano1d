// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Bounded ABI 3 programs and typed native financial templates for Parano1d.

mod bindings;
mod compile;
pub mod native;
mod syntax;
pub mod verify;

pub use bindings::parse_parameters;
pub use compile::{compile, CompiledContract};
pub const MAX_SOURCE_BYTES: usize = syntax::MAX_SOURCE_BYTES;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    pub line: usize,
    pub column: usize,
    pub message: String,
}

impl Error {
    pub(crate) fn plain(message: impl Into<String>) -> Self {
        Self {
            line: 0,
            column: 0,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.line == 0 {
            f.write_str(&self.message)
        } else {
            write!(f, "{}:{}: {}", self.line, self.column, self.message)
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests;

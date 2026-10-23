// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use clap::{Args, Parser, Subcommand};
use noid_pruv::{compile, parse_parameters, verify, MAX_SOURCE_BYTES};

#[derive(Parser)]
#[command(name = "pruv", version, about = "Compile Parano1d native contracts")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Args)]
struct Input {
    source: PathBuf,
    /// JSON bindings; u64 values are decimal strings.
    #[arg(long)]
    params: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Command {
    /// Check or prepare a typed native financial operation.
    Native {
        #[command(subcommand)]
        command: NativeCommand,
    },
    /// Check syntax, types, explicit policy and ABI resource limits.
    Check {
        #[command(flatten)]
        input: Input,
    },
    /// Produce a definition accepted by parano1d-cli contract create.
    Build {
        #[command(flatten)]
        input: Input,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Export the compiled program and its postconditions as SMT-LIB2.
    Smt {
        #[command(flatten)]
        input: Input,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Prove declared postconditions for every successful integer execution.
    Verify {
        #[command(flatten)]
        input: Input,
        #[arg(long, default_value = "z3")]
        z3: PathBuf,
    },
}

#[derive(Subcommand)]
enum NativeCommand {
    /// Validate asset identities, integer amounts and explicit policy bounds.
    Check { source: PathBuf },
    /// Write a walletPreviewNative JSON-RPC request for review.
    Build {
        source: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Write the unchanged request with a reviewed node plan_id.
    Submit {
        source: PathBuf,
        #[arg(long)]
        plan_id: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

fn read(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let file = File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err("input must be a regular file".into());
    }
    let mut bytes = Vec::new();
    file.take(MAX_SOURCE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_SOURCE_BYTES {
        return Err("input exceeds 64 KiB".into());
    }
    Ok(String::from_utf8(bytes)?)
}

fn write(path: Option<&Path>, text: &str) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(path) = path {
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        if let Err(error) = file
            .write_all(text.as_bytes())
            .and_then(|_| file.sync_all())
        {
            drop(file);
            let _ = std::fs::remove_file(path);
            return Err(error.into());
        }
    } else {
        std::io::stdout().lock().write_all(text.as_bytes())?;
    }
    Ok(())
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    if let Command::Native { command } = &cli.command {
        let source = match command {
            NativeCommand::Check { source }
            | NativeCommand::Build { source, .. }
            | NativeCommand::Submit { source, .. } => source,
        };
        let template = noid_pruv::native::NativeTemplate::parse(&read(source)?)
            .map_err(|error| format!("{}:{error}", source.display()))?;
        return match command {
            NativeCommand::Check { .. } => {
                println!(
                    "native operation {}: valid template",
                    template.operation_code()
                );
                Ok(())
            }
            NativeCommand::Build { out, .. } => write(
                out.as_deref(),
                &(serde_json::to_string_pretty(&template.preview_rpc()?)? + "\n"),
            ),
            NativeCommand::Submit { plan_id, out, .. } => write(
                out.as_deref(),
                &(serde_json::to_string_pretty(&template.submit_rpc(plan_id)?)? + "\n"),
            ),
        };
    }
    let input = match &cli.command {
        Command::Check { input }
        | Command::Build { input, .. }
        | Command::Smt { input, .. }
        | Command::Verify { input, .. } => input,
        Command::Native { .. } => unreachable!(),
    };
    let source = read(&input.source)?;
    let parameters = match &input.params {
        Some(path) => {
            parse_parameters(&read(path)?).map_err(|error| format!("{}:{error}", path.display()))?
        }
        None => serde_json::json!({}),
    };
    let contract = compile(&source, &parameters)
        .map_err(|error| format!("{}:{error}", input.source.display()))?;
    match &cli.command {
        Command::Native { .. } => unreachable!(),
        Command::Check { .. } => println!(
            "{}: ABI 3, {}/16 instructions, {}/2 state registers, {} postconditions",
            contract.name(),
            contract.instructions(),
            contract.state_registers(),
            contract.postconditions()
        ),
        Command::Build { out, .. } => write(
            out.as_deref(),
            &(serde_json::to_string_pretty(&contract.definition())? + "\n"),
        )?,
        Command::Smt { out, .. } => write(out.as_deref(), &verify::smt(&contract)?)?,
        Command::Verify { z3, .. } => match verify::verify(&contract, z3)? {
            verify::Verdict::Verified => println!(
                "{}: {} postconditions verified for every successful ABI 3 integer execution",
                contract.name(),
                contract.postconditions()
            ),
            verify::Verdict::Counterexample => {
                return Err("postcondition violated by a successful integer execution".into())
            }
            verify::Verdict::Infeasible => {
                return Err("integer program has no successful execution".into())
            }
        },
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("pruv: {error}");
        std::process::exit(1);
    }
}

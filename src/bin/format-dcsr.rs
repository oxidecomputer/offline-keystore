// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Context;
use clap::Parser;
use lpc55_sign::debug_auth::DebugCredentialSigningRequest;
use oks::config::DcsrSpec;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::PathBuf,
};
use yubihsm::object::Label;

#[derive(Parser, Debug)]
/// Convert a CSR into JSON input format for oks. CSR is taken from stdin.
struct Args {
    /// Label of root keys in CMPA
    #[clap(long, num_args = 1..=4, value_delimiter = ',')]
    root_labels: Vec<Label>,

    /// output file
    #[clap(long)]
    out: Option<PathBuf>,

    /// Label for the entity to sign the CSR.
    label: Label,

    /// DCSR file. Read from stdin if omitted.
    dcsr: Option<PathBuf>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let reader: Box<dyn Read> = match args.dcsr {
        Some(i) => Box::new(File::open(i)?),
        None => Box::new(io::stdin()),
    };

    let dcsr_json = io::read_to_string(reader)?;
    let dcsr: DebugCredentialSigningRequest = serde_json::from_str(&dcsr_json)?;

    let dcsr_spec = DcsrSpec {
        label: args.label,
        root_labels: args.root_labels,
        dcsr,
    };

    let mut writer: Box<dyn Write> = match args.out {
        Some(o) => Box::new(File::create(o)?),
        None => Box::new(io::stdout()),
    };

    serde_json::to_writer_pretty(&mut writer, &dcsr_spec)
        .context("failed to write DcsrSpec to writer")
}

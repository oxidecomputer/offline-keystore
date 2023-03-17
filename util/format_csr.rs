// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use clap::Parser;
use oks::config::CsrSpec;
use std::io;
use yubihsm::object::Label;

#[derive(Parser, Debug)]
/// Convert a CSR into JSON input format for oks. CSR is taken from stdin.
struct Config {
    /// Label for the entity to sign the CSR.
    #[clap(long)]
    label: Label,
}

fn main() -> anyhow::Result<()> {
    let cfg = Config::parse();

    let csr = io::read_to_string(io::stdin())?;

    let csr_spec = CsrSpec {
        label: cfg.label,
        csr,
    };

    println!("{}", csr_spec.json()?);

    Ok(())
}

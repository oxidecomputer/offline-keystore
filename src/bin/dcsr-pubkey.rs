// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use oks::config::DcsrSpec;
use rsa::{
    pkcs1::{EncodeRsaPublicKey, LineEnding},
    pkcs8::EncodePublicKey,
};
use std::{
    fs,
    io::{self, Write},
    path::PathBuf,
};

#[derive(ValueEnum, Copy, Clone, Debug, Default)]
enum Format {
    Pkcs1,
    #[default]
    Spki,
}

#[derive(ValueEnum, Copy, Clone, Debug, Default)]
enum Encoding {
    Der,
    #[default]
    Pem,
}

/// Extract the RSA public key from a DcsrSpec and dump it to stdout in the
/// requested format and encoding.
#[derive(Parser, Debug)]
struct Args {
    /// The encoding used to serialize the public key.
    #[clap(default_value_t, long, value_enum)]
    encoding: Encoding,

    /// The format use to represent the public key.
    #[clap(default_value_t, long, value_enum)]
    format: Format,

    /// Path to a DcsrSpec file.
    dcsr_file: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let json = fs::read_to_string(&args.dcsr_file)
        .context("Reading file name argument to string")?;

    let spec: DcsrSpec = serde_json::from_str(&json)
        .context("Failed to deserialize DcsrSpec from json")?;

    let pub_key = spec.dcsr.debug_public_key;

    match args.encoding {
        Encoding::Der => {
            let der = match args.format {
                Format::Pkcs1 => pub_key.to_pkcs1_der().context(
                    "Get DER encoded, PKCS#1 formatted RSA public key",
                )?,
                Format::Spki => pub_key.to_public_key_der().context(
                    "Get DER encoded, SPKI formatted RSA public key",
                )?,
            };
            io::stdout()
                .write_all(der.as_bytes())
                .context("write encoded public key to stdout")
        }
        Encoding::Pem => {
            let pem = match args.format {
                Format::Pkcs1 => pub_key
                    .to_pkcs1_pem(LineEnding::default())
                    .context("Get PEM encoded PKCS#1 from RSA public key")?,
                Format::Spki => pub_key
                    .to_public_key_pem(LineEnding::default())
                    .context("Get SPKI PEM from RSA public key")?,
            };
            io::stdout()
                .write_all(pem.as_bytes())
                .context("write encoded public key to stdout")
        }
    }
}

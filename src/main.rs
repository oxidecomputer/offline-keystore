// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use clap::{Parser, Subcommand};
use env_logger::Builder;
use log::LevelFilter;
use std::path::PathBuf;
use yubihsm::{Client, Connector, Credentials, UsbConfig};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
/// Create and restore split yubihsm wrap keys
struct Args {
    /// Increase verbosity
    #[clap(long, env)]
    verbose: bool,

    /// Directory where we put backups and certs
    #[clap(long, env, default_value = "oks-public")]
    public: PathBuf,

    /// subcommands
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug, PartialEq)]
enum Command {
    Ca {
        /// Directory where HSM config description and CA state goes
        #[clap(long, env, default_value = "oks-state")]
        state: PathBuf,

        #[command(subcommand)]
        command: CaCommand,
    },
    Hsm {
        #[command(subcommand)]
        command: HsmCommand,
    },
}

#[derive(Subcommand, Debug, PartialEq)]
enum CaCommand {
    /// Initialize an OpenSSL CA for the given key.
    Initialize {
        /// Spec file describing the CA signing key
        #[clap(long, env, default_value = "data/key-request-ecp384.json")]
        key_spec: PathBuf,
    },

    /// Use the CA associated with the provided key spec to sign the
    /// provided CSR.
    Sign {
        #[clap(long, env, default_value = "data/p384-sha384.csrspec.json")]
        csr_spec: PathBuf,
    },
}

#[derive(Subcommand, Debug, PartialEq)]
enum HsmCommand {
    /// Generate keys in YubiHSM from specification.
    Generate {
        #[clap(long, env)]
        key_spec: PathBuf,
    },

    /// Display device info.
    Info,

    /// Initialize the YubiHSM for use in the OKS.
    Initialize {
        #[clap(long, env, default_value = "/dev/usb/lp0")]
        print_dev: PathBuf,
    },

    /// Reset to factory defaults
    Reset,

    /// Restore a previously split aes256-ccm-wrap key
    Restore,
}

// 2 minute to support RSA4K key generation
const TIMEOUT_MS: u64 = 120000;

fn main() -> Result<()> {
    let args = Args::parse();

    let mut builder = Builder::from_default_env();

    let level = if args.verbose {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };
    builder.filter(None, level).init();

    match args.command {
        Command::Ca { command, state } => match command {
            CaCommand::Initialize { key_spec } => {
                oks::ca::initialize(&key_spec, &state, &args.public)
            }
            CaCommand::Sign { csr_spec } => {
                oks::ca::sign(&csr_spec, &state, &args.public)
            }
        },
        Command::Hsm { command } => {
            // Setup authentication credentials:
            // For 'initialize' subcommand we assume the YubiHSM is in its
            // default state: auth key id is 1, password is 'password'.
            // Any other HSM subcommand:
            // - we assume the auth id is the same one we setup when executing
            // the initialize command: 2
            // - the user is prompted for a password
            let (auth_id, passwd) = match command {
                HsmCommand::Initialize { print_dev: _ } => {
                    (1, "password".to_string())
                }
                _ => {
                    (2, rpassword::prompt_password("Enter YubiHSM Password: ")?)
                }
            };

            let config = UsbConfig {
                serial: None,
                timeout_ms: TIMEOUT_MS,
            };
            let connector = Connector::usb(&config);
            let credentials =
                Credentials::from_password(auth_id, passwd.as_bytes());
            let client = Client::open(connector, credentials, true)?;

            match command {
                HsmCommand::Info => oks::hsm::dump_info(&client),
                HsmCommand::Initialize { print_dev } => {
                    oks::hsm::initialize(&client, &args.public, &print_dev)
                }
                HsmCommand::Generate { key_spec } => {
                    oks::hsm::generate(&client, &key_spec, &args.public)
                }
                HsmCommand::Reset => oks::hsm::reset(&client),
                HsmCommand::Restore => oks::hsm::restore(&client),
            }
        }
    }
}

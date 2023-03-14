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

    /// Directory where public data goes
    #[clap(long, env, default_value = "oks-publish")]
    public: PathBuf,

    /// subcommands
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug, PartialEq)]
enum Command {
    Ca {
        /// Spec file describing the CA signing key
        #[clap(long, env, default_value = "data/key-request-ecp384.json")]
        key_spec: PathBuf,

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
    Initialize,

    /// Use the CA associated with the provided key spec to sign the
    /// provided CSR.
    Sign {
        #[clap(long, env, default_value = "data/p384-sha384.csr.pem")]
        csr: PathBuf,
    },
}

#[derive(Subcommand, Debug, PartialEq)]
enum HsmCommand {
    /// Generate keys in YubiHSM from specification.
    Generate {
        #[clap(long, env, default_value = "data/key-request-rsa4k.json")]
        key_spec: PathBuf,
    },
    /// Initialize the YubiHSM for use in the OKS.
    Initialize {
        #[clap(long, env, default_value = "/dev/usb/lp0")]
        print_dev: PathBuf,
    },
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
        Command::Ca {
            command,
            key_spec,
            state,
        } => match command {
            CaCommand::Initialize => {
                oks_util::ca_initialize(&key_spec, &state, &args.public)
            }
            CaCommand::Sign { csr } => {
                oks_util::ca_sign(&key_spec, &csr, &state, &args.public)
            }
        },
        Command::Hsm { command } => {
            // For 'initialize' subcommand we assume the YubiHSM is in its
            // default state: auth key id is 1, password is 'password'.
            // Any other HSM subcommand we assume:
            // - the auth id is 2 which is the id of the auth key created
            //   during initialization
            // - the user will be prompted for a password
            let passwd = match command {
                HsmCommand::Initialize { print_dev: _ } => {
                    "password".to_string()
                }
                _ => rpassword::prompt_password("Enter YubiHSM Password: ")
                    .unwrap(),
            };
            let auth_id = match command {
                HsmCommand::Initialize { print_dev: _ } => 1, // default auth key id for YubiHSM
                _ => 2, // auth key id we create in initialize
            };

            let config = UsbConfig {
                serial: None,
                timeout_ms: TIMEOUT_MS,
            };
            let connector = Connector::usb(&config);
            // this will only work if the default auth key is still available
            // the next step in our process must be: replace the default auth key
            let credentials =
                Credentials::from_password(auth_id, passwd.as_bytes());
            let client = Client::open(connector, credentials, true)?;

            match command {
                HsmCommand::Initialize { print_dev } => {
                    oks_util::hsm_initialize(&client, &args.public, &print_dev)
                }
                HsmCommand::Generate { key_spec } => {
                    oks_util::hsm_generate_key(&client, &key_spec, &args.public)
                }
                HsmCommand::Restore => oks_util::restore(&client),
            }
        }
    }
}

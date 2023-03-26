// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use clap::{Parser, Subcommand};
use env_logger::Builder;
use log::{info, warn, LevelFilter};
use std::{
    fs,
    path::{Path, PathBuf},
    str::FromStr,
};
use yubihsm::{
    object::{Id, Type},
    Client, Connector, Credentials, UsbConfig,
};

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

        /// Path to the YubiHSM PKCS#11 module
        #[clap(
            long,
            env = "OKS_PKCS11_PATH",
            default_value = "/usr/lib/pkcs11/yubihsm_pkcs11.so"
        )]
        pkcs11_path: PathBuf,
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
    /// Export an object identified under wrap.
    Backup {
        /// Object ID: https://developers.yubico.com/YubiHSM2/Concepts/Object_ID.html
        #[clap(long, env)]
        id: Id,

        /// Object type: https://developers.yubico.com/YubiHSM2/Concepts/Object.html
        #[clap(long, env)]
        kind: String,

        /// The file name where the backup is written. If omitted the backup
        /// will be written to a file named according to the object label
        /// with the suffix `backup.json`. If a path privided is a directory
        /// the file will be created in it.
        #[clap(long, env, default_value = "./")]
        file: PathBuf,
    },

    /// Delete object.
    Delete {
        /// Object ID: https://developers.yubico.com/YubiHSM2/Concepts/Object_ID.html
        #[clap(long, env)]
        id: Id,

        /// Object type: https://developers.yubico.com/YubiHSM2/Concepts/Object.html
        #[clap(long, env)]
        kind: String,
    },

    /// Generate keys in YubiHSM from specification.
    Generate {
        #[clap(long, env, default_value = "input")]
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

    /// Restore a previously backed up key.
    Restore {
        /// An optional file name holding the wrapped object to be restored.
        /// If omitted all files with the 'backup.json' extension within the
        /// directory from '--public' will be restored
        #[clap(long, env)]
        file: Option<PathBuf>,
    },

    /// Restore a previously split aes256-ccm-wrap key
    RestoreAll,
}

// 2 minute to support RSA4K key generation
const TIMEOUT_MS: u64 = 120000;

// Create output directories for the commands that need them
fn create_required_dirs(args: &Args) -> Result<()> {
    match &args.command {
        Command::Hsm { command } => match command {
            HsmCommand::Info | HsmCommand::Reset => (),
            _ => make_dir(&args.public)?,
        },
        Command::Ca { command: _, state } => {
            make_dir(state)?;
            make_dir(&args.public)?;
        }
    }

    Ok(())
}

fn make_dir(path: &Path) -> Result<()> {
    if !path.try_exists()? {
        // public directory doesn't exist, create it
        warn!(
            "required directory does not exist, creating: \"{}\"",
            path.display()
        );
        Ok(fs::create_dir_all(path)?)
    } else if !path.is_dir() {
        Err(anyhow::anyhow!(
            "directory provided is not a directory: \"{}\"",
            path.display()
        ))
    } else {
        Ok(())
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    let mut builder = Builder::from_default_env();

    let level = if args.verbose {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };
    builder.filter(None, level).init();

    create_required_dirs(&args)?;

    match args.command {
        Command::Ca { command, state } => match command {
            CaCommand::Initialize {
                key_spec,
                pkcs11_path,
            } => oks::ca::initialize(
                &key_spec,
                &pkcs11_path,
                &state,
                &args.public,
            ),
            CaCommand::Sign { csr_spec } => {
                oks::ca::sign(&csr_spec, &state, &args.public)
            }
        },
        Command::Hsm { command } => {
            // Setup authentication credentials:
            // For 'initialize' and 'restore-wrap' subcommands we assume the
            // YubiHSM is in its default state: auth key id is 1, password is
            // 'password'. Any other HSM subcommand:
            // - we assume the auth id is the same one we setup when executing
            // the initialize command: 2
            // - the user is prompted for a password
            let (auth_id, passwd) = match command {
                HsmCommand::Initialize { print_dev: _ }
                | HsmCommand::RestoreAll => (1, "password".to_string()),
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
                HsmCommand::Backup { id, kind, file } => {
                    // this is a bit weird but necessary because the Type type
                    // returns () on error, not a type implementing std::Error
                    let kind = match Type::from_str(&kind) {
                        Ok(k) => k,
                        Err(_) => {
                            return Err(anyhow::anyhow!("Invalid object type."))
                        }
                    };
                    oks::hsm::backup(&client, id, kind, file)
                }
                HsmCommand::Delete { id, kind } => {
                    // this is a bit weird but necessary because the Type type
                    // returns () on error, not a type implementing std::Error
                    let kind = match Type::from_str(&kind) {
                        Ok(k) => k,
                        Err(_) => {
                            return Err(anyhow::anyhow!("Invalid object type."))
                        }
                    };
                    oks::hsm::delete(&client, id, kind)
                }
                HsmCommand::Info => oks::hsm::dump_info(&client),
                HsmCommand::Initialize { print_dev } => {
                    oks::hsm::initialize(&client, &args.public, &print_dev)
                }
                HsmCommand::Generate { key_spec } => {
                    oks::hsm::generate(&client, &key_spec, &args.public)
                }
                HsmCommand::Reset => oks::hsm::reset(&client),
                HsmCommand::Restore { file } => {
                    let file = match file {
                        Some(p) => p,
                        None => args.public,
                    };
                    oks::hsm::restore(&client, file)
                }
                HsmCommand::RestoreAll => {
                    info!("Restoring HSM from backup");
                    info!("Restoring backup / wrap key from shares");
                    oks::hsm::restore_wrap(&client)?;
                    info!(
                        "Restoring keys from backups in: \"{}\"",
                        &args.public.display()
                    );
                    oks::hsm::restore(&client, &args.public)?;
                    info!("Deleting default authentication key");
                    oks::hsm::delete(&client, 1, Type::AuthenticationKey)
                }
            }
        }
    }
}

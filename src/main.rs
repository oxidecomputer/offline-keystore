// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use clap::{Parser, Subcommand};
use env_logger::Builder;
use log::{info, LevelFilter};
use std::{
    env, fs,
    path::{Path, PathBuf},
};
use yubihsm::object::{Id, Type};

use oks::config::ENV_PASSWORD;
use oks::hsm::Hsm;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
/// Create and restore split yubihsm wrap keys
struct Args {
    /// Increase verbosity
    #[clap(long, env)]
    verbose: bool,

    /// Directory where we put certs and attestations
    #[clap(long, env, default_value = "output")]
    output: PathBuf,

    /// Directory where we put KeySpec, CA state and backups
    #[clap(long, env, default_value = "ca-state")]
    state: PathBuf,

    /// subcommands
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug, PartialEq)]
enum Command {
    Ca {
        #[command(subcommand)]
        command: CaCommand,
    },
    Hsm {
        /// ID of authentication credential
        #[clap(long, env)]
        auth_id: Option<Id>,

        #[command(subcommand)]
        command: HsmCommand,
    },
    /// Execute the OKS provisioning ceremony in a single command. This
    /// is equivalent to executing `hsm initialize`, `hsm generate`,
    /// `ca initialize`, and `ca sign`.
    Ceremony {
        #[clap(long, env, default_value = "input")]
        csr_spec: PathBuf,

        #[clap(long, env, default_value = "input")]
        key_spec: PathBuf,

        /// Path to the YubiHSM PKCS#11 module
        #[clap(
            long,
            env = "OKS_PKCS11_PATH",
            default_value = "/usr/lib/pkcs11/yubihsm_pkcs11.so"
        )]
        pkcs11_path: PathBuf,

        #[clap(long, env, default_value = "/dev/usb/lp0")]
        print_dev: PathBuf,
    },
}

#[derive(Subcommand, Debug, PartialEq)]
/// Commands for operating on the CAs associated with keys in the HSM.
enum CaCommand {
    /// Initialize an OpenSSL CA for the given key.
    Initialize {
        /// Spec file describing the CA signing key
        #[clap(long, env, default_value = "input")]
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
        #[clap(long, env, default_value = "input")]
        csr_spec: PathBuf,
    },
}

#[derive(Subcommand, Clone, Debug, PartialEq)]
#[clap(verbatim_doc_comment)]
/// Commands for interacting with the YubiHSM2 during key ceremonies.
/// Behavior of this command is influenced by the following environment
/// variables:
/// - OKS_PASSWORD - if set this command will use the value from this
///   variable for authention with the HSM
/// - OKS_NEW_PASSWORD - if set this command will use the value from this
///   variable as the password for a newly created admin auth credential
enum HsmCommand {
    /// Generate keys in YubiHSM from specification.
    Generate {
        #[clap(long, env, default_value = "input")]
        key_spec: PathBuf,
    },

    /// Initialize the YubiHSM for use in the OKS.
    Initialize {
        #[clap(long, env, default_value = "/dev/usb/lp0")]
        print_dev: PathBuf,
    },

    /// Restore a previously split aes256-ccm-wrap key
    Restore,

    /// Get serial number from YubiHSM and dump to console.
    SerialNumber,
}

fn make_dir(path: &Path) -> Result<()> {
    if !path.try_exists()? {
        // output directory doesn't exist, create it
        info!(
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

/// Get auth_id, pick reasonable defaults if not set.
fn get_auth_id(auth_id: Option<Id>, command: &HsmCommand) -> Id {
    match auth_id {
        // if auth_id is set by the caller we use that value
        Some(a) => a,
        None => match command {
            // for these HSM commands we assume YubiHSM2 is in its
            // default state and we use the default auth credentials:
            // auth_id 1
            HsmCommand::Initialize { print_dev: _ }
            | HsmCommand::Restore
            | HsmCommand::SerialNumber => 1,
            // otherwise we assume the auth key that we create is
            // present: auth_id 2
            _ => 2,
        },
    }
}

/// Get password either from environment, the YubiHSM2 default, or challenge
/// the user with a password prompt.
fn get_passwd(auth_id: Option<Id>, command: &HsmCommand) -> Result<String> {
    match env::var(ENV_PASSWORD).ok() {
        Some(s) => Ok(s),
        None => {
            if auth_id.is_some() {
                // if auth_id was set by the caller but not the password we
                // prompt for the password
                Ok(rpassword::prompt_password("Enter YubiHSM Password: ")?)
            } else {
                match command {
                    // if password isn't set, auth_id isn't set, and
                    // the command is one of these, we assume the
                    // YubiHSM2 is in its default state so we use the
                    // default password
                    HsmCommand::Initialize { print_dev: _ }
                    | HsmCommand::Restore
                    | HsmCommand::SerialNumber => Ok("password".to_string()),
                    // otherwise prompt the user for the password
                    _ => Ok(rpassword::prompt_password(
                        "Enter YubiHSM Password: ",
                    )?),
                }
            }
        }
    }
}

/// Perform all operations that make up the ceremony for provisioning an
/// offline keystore.
fn do_ceremony(
    csr_spec: &Path,
    key_spec: &Path,
    pkcs11_path: &Path,
    print_dev: &Path,
    args: &Args,
) -> Result<()> {
    {
        // get password according to rules for the Initialize command
        let cmd = HsmCommand::Initialize {
            print_dev: print_dev.to_path_buf(),
        };
        let auth_id = get_auth_id(None, &cmd);
        let passwd = get_passwd(None, &cmd)?;

        let hsm = Hsm::new(auth_id, &passwd, &args.output, &args.state)?;
        hsm.initialize(print_dev)?;
    }
    {
        // get password according to rules for the Generate command
        let cmd = HsmCommand::Generate {
            key_spec: key_spec.to_path_buf(),
        };
        let auth_id = get_auth_id(None, &cmd);
        let passwd = get_passwd(None, &cmd)?;

        let hsm = Hsm::new(auth_id, &passwd, &args.output, &args.state)?;
        hsm.generate(key_spec)?;
    }
    oks::ca::initialize(key_spec, pkcs11_path, &args.state, &args.output)?;
    oks::ca::sign(csr_spec, &args.state, &args.output)
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

    make_dir(&args.output)?;
    make_dir(&args.state)?;

    match args.command {
        Command::Ca { command } => match command {
            CaCommand::Initialize {
                key_spec,
                pkcs11_path,
            } => oks::ca::initialize(
                &key_spec,
                &pkcs11_path,
                &args.state,
                &args.output,
            ),
            CaCommand::Sign { csr_spec } => {
                oks::ca::sign(&csr_spec, &args.state, &args.output)
            }
        },
        Command::Hsm { auth_id, command } => {
            let passwd = get_passwd(auth_id, &command)?;
            let auth_id = get_auth_id(auth_id, &command);
            let hsm = Hsm::new(auth_id, &passwd, &args.output, &args.state)?;

            match command {
                HsmCommand::Initialize { print_dev } => {
                    hsm.initialize(&print_dev)
                }
                HsmCommand::Generate { key_spec } => hsm.generate(&key_spec),
                HsmCommand::Restore => {
                    hsm.restore_wrap()?;
                    oks::hsm::restore(&hsm.client, &hsm.state_dir)?;
                    info!("Deleting default authentication key");
                    oks::hsm::delete(&hsm.client, 1, Type::AuthenticationKey)
                }
                HsmCommand::SerialNumber => oks::hsm::dump_sn(&hsm.client),
            }
        }
        Command::Ceremony {
            ref csr_spec,
            ref key_spec,
            ref pkcs11_path,
            ref print_dev,
        } => do_ceremony(csr_spec, key_spec, pkcs11_path, print_dev, &args),
    }
}

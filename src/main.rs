// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use clap::{Parser, Subcommand};
use env_logger::Builder;
use log::{debug, error, info, LevelFilter};
use std::{
    env, fs,
    path::{Path, PathBuf},
};
use yubihsm::object::{Id, Type};
use zeroize::Zeroizing;

use oks::config::{ENV_NEW_PASSWORD, ENV_PASSWORD};
use oks::hsm::{self, Hsm};

const PASSWD_PROMPT: &str = "Enter new HSM password: ";
const PASSWD_PROMPT2: &str = "Enter password again to confirm: ";

const GEN_PASSWD_LENGTH: usize = 16;

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

        #[clap(long, env)]
        /// Challenge the caller for a new password, don't generate a
        /// random one for them.
        passwd_challenge: bool,
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

        #[clap(long, env)]
        /// Challenge the caller for a new password, don't generate a
        /// random one for them.
        passwd_challenge: bool,
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
            HsmCommand::Initialize {
                print_dev: _,
                passwd_challenge: _,
            }
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
                    HsmCommand::Initialize {
                        print_dev: _,
                        passwd_challenge: _,
                    }
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

/// get a new password from the environment or by issuing a challenge the user
fn get_new_passwd(hsm: Option<&Hsm>) -> Result<Zeroizing<String>> {
    match env::var(ENV_NEW_PASSWORD).ok() {
        // prefer new password from env above all else
        Some(s) => {
            info!("got password from env");
            Ok(Zeroizing::new(s))
        }
        None => match hsm {
            // use the HSM otherwise if available
            Some(hsm) => {
                info!("Generating random password");
                Ok(Zeroizing::new(hsm.rand_string(GEN_PASSWD_LENGTH)?))
            }
            // last option: challenge the caller
            None => loop {
                let password =
                    Zeroizing::new(rpassword::prompt_password(PASSWD_PROMPT)?);
                let password2 =
                    Zeroizing::new(rpassword::prompt_password(PASSWD_PROMPT2)?);
                if password != password2 {
                    error!("the passwords entered do not match");
                } else {
                    debug!("got the same password twice");
                    return Ok(password);
                }
            },
        },
    }
}

/// Perform all operations that make up the ceremony for provisioning an
/// offline keystore.
fn do_ceremony(
    csr_spec: &Path,
    key_spec: &Path,
    pkcs11_path: &Path,
    print_dev: &Path,
    challenge: bool,
    args: &Args,
) -> Result<()> {
    // this is mut so we can zeroize when we're done
    let passwd_new = {
        // assume YubiHSM is in default state: use default auth credentials
        let passwd = "password".to_string();
        let hsm = Hsm::new(1, &passwd, &args.output, &args.state)?;

        hsm.new_split_wrap(print_dev)?;
        info!("Collecting YubiHSM attestation cert.");
        hsm.dump_attest_cert::<String>(None)?;

        let passwd = if challenge {
            get_new_passwd(None)?
        } else {
            let passwd = get_new_passwd(Some(&hsm))?;
            hsm::print_password(print_dev, &passwd)?;
            passwd
        };
        hsm.replace_default_auth(&passwd)?;
        passwd
    };
    {
        // use new password to auth
        let hsm = Hsm::new(2, &passwd_new, &args.output, &args.state)?;
        hsm.generate(key_spec)?;
    }
    // set env var for oks::ca module to pickup for PKCS11 auth
    env::set_var(ENV_PASSWORD, &passwd_new);
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
                HsmCommand::Initialize {
                    print_dev,
                    passwd_challenge,
                } => {
                    hsm.new_split_wrap(&print_dev)?;
                    let passwd_new = if passwd_challenge {
                        get_new_passwd(None)?
                    } else {
                        let passwd = get_new_passwd(Some(&hsm))?;
                        hsm::print_password(&print_dev, &passwd)?;
                        passwd
                    };
                    hsm.dump_attest_cert::<String>(None)?;
                    hsm.replace_default_auth(&passwd_new)
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
            passwd_challenge,
        } => do_ceremony(
            csr_spec,
            key_spec,
            pkcs11_path,
            print_dev,
            passwd_challenge,
            &args,
        ),
    }
}

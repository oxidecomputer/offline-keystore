// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use clap::{Parser, Subcommand};
use env_logger::Builder;
use log::LevelFilter;
use std::{path::PathBuf, str::FromStr};
use yubihsm::{
    object::{Id, Type},
    AuditOption, Client, Connector, Credentials, UsbConfig,
};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
/// Create and restore split yubihsm wrap keys
struct Args {
    /// ID of authentication credential
    #[clap(long, env)]
    auth_id: Option<Id>,

    /// subcommands
    #[command(subcommand)]
    command: Command,

    /// Increase verbosity
    #[clap(long, env)]
    verbose: bool,
}

#[derive(Subcommand, Clone, Debug, PartialEq)]
enum LogCommand {
    /// dump log serialized to JSON
    Json,

    /// Set the index of the last entry consumed from the HSM audit log.
    /// This causes entries with a lower index to be deleted.
    SetIndex {
        /// Last entry consumed.
        index: u16,
    },
}

#[derive(Subcommand, Clone, Debug, PartialEq)]
enum AuditCommand {
    /// Set the `force-audit` option to the disabled state.
    Disable,

    /// Set the `force-audit` option to the enabled state.
    Enable,

    /// Set the `force-audit` option to the locked state.
    Lock,

    /// Query the state of the `force-audit` option.
    Query,

    /// Manage the audit log.
    Log {
        #[command(subcommand)]
        command: Option<LogCommand>,
    },
}

#[derive(Subcommand, Debug, PartialEq)]
enum Command {
    /// Get / Set the state of the `force-audit` option.
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },

    /// Export an object identified under wrap.
    Backup {
        /// Object ID: https://developers.yubico.com/YubiHSM2/Concepts/Object_ID.html
        #[clap(long, env)]
        id: Id,

        /// Object type: https://developers.yubico.com/YubiHSM2/Concepts/Object.html
        #[clap(long, env)]
        kind: String,

        /// The file name where the backup is written.
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

    /// Display device info.
    Info,

    /// Reset to factory defaults
    Reset,

    /// Restore a previously backed up key.
    Restore {
        /// File name holding the wrapped object to be restored.
        #[clap(long, env)]
        file: PathBuf,
    },
}

const TIMEOUT_MS: u64 = 300000;

fn main() -> Result<()> {
    let args = Args::parse();

    let mut builder = Builder::from_default_env();

    let level = if args.verbose {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };
    builder.filter(None, level).init();

    let passwd = rpassword::prompt_password("Enter YubiHSM Password: ")?;
    let auth_id = args.auth_id.unwrap_or(1);

    let config = UsbConfig {
        serial: None,
        timeout_ms: TIMEOUT_MS,
    };
    let connector = Connector::usb(&config);

    let credentials = Credentials::from_password(auth_id, passwd.as_bytes());
    let client = Client::open(connector, credentials, true)?;

    match args.command {
        Command::Audit { command } => match command {
            AuditCommand::Disable => {
                Ok(client.set_force_audit_option(AuditOption::Off)?)
            }
            AuditCommand::Enable => {
                Ok(client.set_force_audit_option(AuditOption::On)?)
            }
            AuditCommand::Lock => Ok(oks::hsm::audit_lock(&client)?),
            AuditCommand::Query => {
                let state = client.get_force_audit_option()?;
                println!("{state:?}");
                Ok(())
            }
            AuditCommand::Log { command } => match command {
                None | Some(LogCommand::Json) => {
                    let entries = client.get_log_entries()?;
                    if entries.entries.last().is_some() {
                        println!("{}", serde_json::to_string_pretty(&entries)?);
                        Ok(())
                    } else {
                        Err(anyhow::anyhow!("audit log contains no entries"))
                    }
                }
                Some(LogCommand::SetIndex { index }) => {
                    Ok(client.set_log_index(index)?)
                }
            },
        },
        Command::Backup { id, kind, file } => {
            // this is a bit weird but necessary because the Type type
            // returns () on error, not a type implementing std::Error
            let kind = match Type::from_str(&kind) {
                Ok(k) => k,
                Err(_) => return Err(anyhow::anyhow!("Invalid object type.")),
            };
            oks::hsm::backup_object(&client, id, kind, file)
        }
        Command::Delete { id, kind } => {
            // this is a bit weird but necessary because the Type type
            // returns () on error, not a type implementing std::Error
            let kind = match Type::from_str(&kind) {
                Ok(k) => k,
                Err(_) => return Err(anyhow::anyhow!("Invalid object type.")),
            };
            oks::hsm::delete(&client, id, kind)
        }
        Command::Info => oks::hsm::dump_info(&client),
        Command::Reset => oks::hsm::reset(&client),
        Command::Restore { file } => oks::hsm::restore(&client, file),
    }
}

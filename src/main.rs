// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use env_logger::Builder;
use log::LevelFilter;
use log::{debug, info};
use static_assertions as sa;
use std::fs;
use std::io;
use std::path::PathBuf;
use tempfile::TempDir;

use hex::ToHex;

use yubihsm::object::{Id, Label};
use yubihsm::{
    wrap, Capability, Client, Connector, Credentials, Domain, UsbConfig,
};

const ALG: wrap::Algorithm = wrap::Algorithm::Aes256Ccm;
// assign wrap key to all domains and all caps so it can backup / restore
// everything
const CAPS: Capability = Capability::all();
const DELEGATED_CAPS: Capability = Capability::all();
const DOMAIN: Domain = Domain::all();
const ID: Id = 0x1;
const KEY_LEN: usize = 32;
const LABEL: &str = "backup";

const THRESHOLD: u8 = 3;
const SHARES: u8 = 5;

// TODO: convert from DEFAULT_AUTHENTICATION_KEY_ID
const AUTH_KEY_ID: &str = "1";

sa::const_assert!(THRESHOLD <= SHARES);

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
/// Create and restore split yubihsm wrap keys
struct Args {
    /// Increase verbosity
    #[clap(long, env)]
    verbose: bool,

    /// Directory where HSM config description and CA state goes
    /// TODO: coordinate this with OS?
    #[clap(long, env, default_value = "./keystore-state")]
    state: PathBuf,

    /// Directory where public data goes
    /// TODO: coordinate this with OS?
    #[clap(long, env, default_value = "./public")]
    public: PathBuf,

    #[clap(long, env, default_value = AUTH_KEY_ID)]
    auth_key_id: Id,

    #[clap(long, env, default_value = "password")]
    auth_passwd: String,

    /// subcommands
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Create a new aes256-ccm-wrap key and split it into shares
    Create,
    /// Generate keys in YubiHSM from specification
    Generate {
        #[clap(long, env, default_value = "data/key-request-rsa4k.json")]
        key_spec: PathBuf,
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

    // connect to the first YubiHSM found
    // NOTE: don't use the http connector unless you have to
    // yubihsm-shell commands
    //let config = HttpConfig {
    //    addr: "127.0.0.1".to_owned(),
    //    port: 12345,
    //    timeout_ms: TIMEOUT_MS,
    //};
    //let connector = Connector::http(&config);
    let config = UsbConfig {
        serial: None,
        timeout_ms: TIMEOUT_MS,
    };
    let connector = Connector::usb(&config);
    // this will only work if the default auth key is still available
    // the next step in our process must be: replace the default auth key
    let credentials = Credentials::from_password(
        args.auth_key_id,
        args.auth_passwd.as_bytes(),
    );
    let client = Client::open(connector, credentials, true)?;

    match args.command {
        Command::Create => create(&client, &args.public),
        Command::Generate { key_spec } => {
            yubihsm_split::generate(&client, &key_spec)
        }
        Command::Restore => restore(&client),
    }
}

fn restore(client: &Client) -> Result<()> {
    let mut shares: Vec<String> = Vec::new();

    for i in 1..=THRESHOLD {
        println!("Enter share[{}]: ", i);
        shares.push(io::stdin().lines().next().unwrap().unwrap());
    }

    for (i, share) in shares.iter().enumerate() {
        println!("share[{}]: {}", i, share);
    }

    let wrap_key =
        rusty_secrets::recover_secret(shares).unwrap_or_else(|err| {
            println!("Unable to recover key: {}", err);
            std::process::exit(1);
        });

    debug!("restored wrap key: {}", wrap_key.encode_hex::<String>());

    // put restored wrap key the YubiHSM as an Aes256Ccm wrap key
    let id = client
        .put_wrap_key(
            ID,
            Label::from_bytes(LABEL.as_bytes())?,
            DOMAIN,
            CAPS,
            DELEGATED_CAPS,
            ALG,
            wrap_key,
        )
        .with_context(|| {
            format!(
                "Failed to put wrap key into YubiHSM domains {:?} with id {}",
                DOMAIN, ID
            )
        })?;
    info!("wrap id: {}", id);

    Ok(())
}

fn create(client: &Client, out_dir: &PathBuf) -> Result<()> {
    // get 32 bytes from YubiHSM PRNG
    // TODO: zeroize
    let wrap_key = client.get_pseudo_random(KEY_LEN)?;
    info!("got {} bytes from YubiHSM PRNG", KEY_LEN);
    debug!("got wrap key: {}", wrap_key.encode_hex::<String>());

    // put 32 random bytes into the YubiHSM as an Aes256Ccm wrap key
    let id = client
        .put_wrap_key::<Vec<u8>>(
            ID,
            Label::from_bytes(LABEL.as_bytes())?,
            DOMAIN,
            CAPS,
            DELEGATED_CAPS,
            ALG,
            wrap_key.clone(),
        )
        .with_context(|| {
            format!(
                "Failed to put wrap key into YubiHSM domains {:?} with id {}",
                DOMAIN, ID
            )
        })?;
    info!("wrap id: {}", id);

    // make tmpdir, put everything here, copy to out_dir when we're done
    let temp_dir = TempDir::new()?;
    debug!("temp_dir: {}", temp_dir.path().to_string_lossy());

    // do the stuff from replace-auth.sh
    yubihsm_split::personalize(client, id, temp_dir.path())?;

    let paths = fs::read_dir(&temp_dir)?;
    let mut from_paths = Vec::new();
    for path in paths {
        from_paths.push(path?.path());
    }

    debug!("moving {:#?} to {}", &from_paths, out_dir.display());
    fs_extra::move_items(
        &from_paths,
        out_dir,
        &fs_extra::dir::CopyOptions::new(),
    )?;

    let shares = rusty_secrets::generate_shares(THRESHOLD, SHARES, &wrap_key)
        .with_context(|| {
        format!(
            "Failed to split secret into {} shares with threashold {}",
            SHARES, THRESHOLD
        )
    })?;

    println!(
        "WARNING: The wrap / backup key has been created and stored in the\n\
        YubiHSM. It will now be split into {} key shares. The operator must\n\
        record these shares as they're displayed. Failure to do so will\n\
        result in the inability to reconstruct this key and restore\n\
        backups.\n\n\
        Press enter to begin the key share recording process ...",
        SHARES
    );

    wait_for_line();
    clear_screen();

    for (i, share) in shares.iter().enumerate() {
        let share_num = i + 1;
        println!(
            "When key custodian {share} is steated, press enter to display \
            share {share}",
            share = share_num
        );
        wait_for_line();

        // Can we generate a QR code, photograph it & then recover the key by
        // reading them back through the camera?
        println!("\n{}\n", share);
        println!("When you are done recording this key share, press enter");
        wait_for_line();
        clear_screen();
    }

    Ok(())
}

/// This "clears" the screen using terminal control characters. If your
/// terminal has a scroll bar that can be used to scroll back to previous
/// screens that had been "cleared".
fn clear_screen() {
    print!("{esc}[2J{esc}[1;1H", esc = 27 as char);
}

/// This function is used when displaying key shares as a way for the user to
/// control progression through the key shares displayed in the terminal.
fn wait_for_line() {
    let _ = io::stdin().lines().next().unwrap().unwrap();
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{Context, Result};
use clap::Parser;
use env_logger::Builder;
use log::LevelFilter;
use log::{debug, info};
use static_assertions as sa;
use std::io;

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

sa::const_assert!(THRESHOLD <= SHARES);

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Get loud
    #[clap(long, env)]
    verbose: bool,
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

    // connect to the first YubiHSM found over USB
    // NOTE: yubihsm-connector is not required
    let connector = Connector::usb(&UsbConfig::default());
    // this will only work if the default auth key is still available
    // the next step in our process must be: replace the default auth key
    let credentials = Credentials::default();
    let client = Client::open(connector, credentials, true)?;

    // get 32 bytes from YubiHSM PRNG
    let wrap_key = client.get_pseudo_random(KEY_LEN)?;
    debug!("got {} bytes from YubiHSM PRNG", KEY_LEN);

    // put 32 random bytes into the YubiHSM as an Aes256Ccm wrap key
    let id = client
        .put_wrap_key(
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

fn clear_screen() {
    print!("{esc}[2J{esc}[1;1H", esc = 27 as char);
}

fn wait_for_line() {
    let _ = io::stdin().lines().next().unwrap().unwrap();
}

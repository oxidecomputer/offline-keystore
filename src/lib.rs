// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{Context, Result};
use hex::ToHex;
use log::{debug, error, info};
use static_assertions as sa;
use std::{
    fs, io,
    path::{Path, PathBuf},
    str::FromStr,
};
use tempfile::TempDir;
use thiserror::Error;
use yubihsm::{
    authentication::{self, Key, DEFAULT_AUTHENTICATION_KEY_ID},
    object::{Id, Label, Type},
    wrap, Capability, Client, Domain,
};
use zeroize::Zeroize;

pub mod config;

const ALG: wrap::Algorithm = wrap::Algorithm::Aes256Ccm;
const CAPS: Capability = Capability::all();
const DELEGATED_CAPS: Capability = Capability::all();
const DOMAIN: Domain = Domain::all();
const ID: Id = 0x1;
const KEY_LEN: usize = 32;
const LABEL: &str = "backup";

const SHARES: u8 = 5;
const THRESHOLD: u8 = 3;
sa::const_assert!(THRESHOLD <= SHARES);

#[derive(Error, Debug)]
pub enum HsmError {
    #[error("failed conversion from YubiHSM Domain")]
    BadDomain,
    #[error("failed conversion from YubiHSM Label")]
    BadLabel,
    #[error("your yubihms is broke")]
    Version,
}

const PASSWD_PROMPT: &str = "Enter new HSM password: ";
const PASSWD_PROMPT2: &str = "Enter password again to confirm: ";

/// Generate an asymmetric key from the provided specification.
pub fn generate(client: &Client, key_spec: &Path) -> Result<()> {
    let json = fs::read_to_string(key_spec)?;
    debug!("spec as json: {}", json);

    let spec = config::KeySpec::from_str(&json)?;
    debug!("KeySpec from {}: {:#?}", key_spec.display(), spec);

    let id = client.generate_asymmetric_key(
        spec.id,
        spec.label,
        spec.domain,
        spec.capabilities,
        spec.algorithm,
    )?;
    debug!("new {:#?} key w/ id: {}", spec.algorithm, id);
    Ok(())
}

// consts for our authentication credential
const AUTH_DOMAINS: Domain = Domain::all();
const AUTH_CAPS: Capability = Capability::all();
const AUTH_DELEGATED: Capability = Capability::all();
const AUTH_ID: Id = 2;
const AUTH_LABEL: &str = "admin";

/// This function prompts the user to enter M of the N backup shares. It
/// uses these shares to reconstitute the wrap key. This wrap key can then
/// be used to restore previously backed up / export wrapped keys.
pub fn restore(client: &Client) -> Result<()> {
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

/// Initialize a new YubiHSM 2 by creating:
/// - a new wap key for backup
/// - a new auth key derived from a user supplied password
/// This new auth key is backed up / exported under wrap using the new wrap
/// key. This backup is written to the provided directory path. Finally this
/// function removes the default authentication credentials.
pub fn create(client: &Client, out_dir: &PathBuf) -> Result<()> {
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
    personalize(client, id, temp_dir.path())?;

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

// create a new auth key, remove the default auth key, then export the new
// auth key under the wrap key with the provided id
fn personalize(client: &Client, wrap_id: Id, out_dir: &Path) -> Result<()> {
    debug!(
        "personalizing with wrap key {} and out_dir {}",
        wrap_id,
        out_dir.display()
    );
    // get a new password from the user
    let mut password = loop {
        let password = rpassword::prompt_password(PASSWD_PROMPT).unwrap();
        let mut password2 = rpassword::prompt_password(PASSWD_PROMPT2).unwrap();
        if password != password2 {
            error!("the passwords entered do not match");
        } else {
            password2.zeroize();
            break password;
        }
    };
    debug!("got the same password twice: {}", password);

    // not compatible with Zeroizing wrapper
    let auth_key = Key::derive_from_password(password.as_bytes());

    debug!("putting new auth key from provided password");
    // create a new auth key
    client.put_authentication_key(
        AUTH_ID,
        AUTH_LABEL.into(),
        AUTH_DOMAINS,
        AUTH_CAPS,
        AUTH_DELEGATED,
        authentication::Algorithm::default(), // can't be used in const
        auth_key,
    )?;

    debug!("deleting default auth key");
    client.delete_object(
        DEFAULT_AUTHENTICATION_KEY_ID,
        Type::AuthenticationKey,
    )?;

    debug!("exporting new auth key under wrap-key w/ id: {}", wrap_id);
    let msg =
        client.export_wrapped(wrap_id, Type::AuthenticationKey, AUTH_ID)?;

    // include additional metadata (enough to reconstruct current state)?
    let msg_json = serde_json::to_string(&msg)?;

    debug!("msg_json: {:#?}", msg_json);

    // we need to append a name for our file
    let mut out_dir = out_dir.to_path_buf();
    out_dir.push("auth.json");

    debug!("writing to: {}", out_dir.display());
    fs::write(out_dir, msg_json)?;

    password.zeroize();

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

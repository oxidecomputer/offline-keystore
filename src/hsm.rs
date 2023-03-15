// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{Context, Result};
use hex::ToHex;
use log::{debug, error, info};
use static_assertions as sa;
use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    str::FromStr,
};
use thiserror::Error;
use yubihsm::{
    authentication::{self, Key, DEFAULT_AUTHENTICATION_KEY_ID},
    object::{Id, Label, Type},
    wrap, Capability, Client, Domain,
};
use zeroize::Zeroize;

use crate::config::KeySpec;

const KEYSPEC_EXT: &str = ".keyspec.json";
const WRAP_ID: Id = 1;

const ALG: wrap::Algorithm = wrap::Algorithm::Aes256Ccm;
const CAPS: Capability = Capability::all();
const DELEGATED_CAPS: Capability = Capability::all();
const DOMAIN: Domain = Domain::all();
const ID: Id = 0x1;
const KEY_LEN: usize = 32;
const LABEL: &str = "backup";

const PASSWD_PROMPT: &str = "Enter new HSM password: ";
const PASSWD_PROMPT2: &str = "Enter password again to confirm: ";

const SHARES: u8 = 5;
const THRESHOLD: u8 = 3;
sa::const_assert!(THRESHOLD <= SHARES);

#[derive(Error, Debug)]
pub enum HsmError {
    #[error("path not a directory")]
    BadSpecDirectory,
    #[error("failed conversion from YubiHSM Domain")]
    BadDomain,
    #[error("failed conversion from YubiHSM Label")]
    BadLabel,
    #[error("Invalid purpose for root CA key")]
    BadPurpose,
    #[error("your yubihms is broke")]
    Version,
}

pub fn generate_key_batch(
    client: &Client,
    spec_dir: &Path,
    out_dir: &Path,
) -> Result<()> {
    info!("generating keys in batch mode from: {:?}", spec_dir);
    let mut paths: Vec<PathBuf> = Vec::new();
    for element in fs::read_dir(spec_dir)? {
        match element {
            Ok(e) => {
                let path = e.path();
                if path.to_string_lossy().ends_with(KEYSPEC_EXT) {
                    paths.push(path);
                }
            }
            Err(_) => continue,
        }
    }

    // no need for paths to be mutable past this point
    let paths = paths;
    for path in paths {
        info!("generating key for spec: {:?}", path);
        generate_key(client, &path, out_dir)?;
    }

    Ok(())
}

/// Generate an asymmetric key from the provided specification.
pub fn generate_key(
    client: &Client,
    key_spec: &Path,
    out_dir: &Path,
) -> Result<()> {
    let json = fs::read_to_string(key_spec)?;
    debug!("spec as json: {}", json);

    let spec = KeySpec::from_str(&json)?;
    debug!("KeySpec from {}: {:#?}", key_spec.display(), spec);

    let id = client.generate_asymmetric_key(
        spec.id,
        spec.label.clone(),
        spec.domain,
        spec.capabilities,
        spec.algorithm,
    )?;
    debug!("new {:#?} key w/ id: {}", spec.algorithm, id);

    debug!(
        "exporting new asymmetric key under wrap-key w/ id: {}",
        WRAP_ID
    );
    let msg = client.export_wrapped(WRAP_ID, Type::AsymmetricKey, id)?;
    let msg_json = serde_json::to_string(&msg)?;

    debug!("exported asymmetric key: {:#?}", msg_json);

    let mut out_pathbuf = out_dir.to_path_buf();
    out_pathbuf.push(format!("{}.wrap.json", spec.label));

    debug!("writing to: {}", out_pathbuf.display());
    fs::write(out_pathbuf, msg_json)?;

    // get yubihsm attestation
    info!("Getting attestation for key with label: {}", spec.label);
    let attest_cert = client.sign_attestation_certificate(spec.id, None)?;
    let attest_path = out_dir.join(format!("{}.attest.cert.pem", spec.label));
    fs::write(attest_path, attest_cert)?;

    Ok(())
}

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
pub fn initialize(
    client: &Client,
    out_dir: &Path,
    print_dev: &Path,
) -> Result<()> {
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
    debug!("wrap id: {}", id);
    // Future commands assume that our wrap key has id 1. If we got a wrap
    // key with any other id the HSM isn't in the state we think it is.
    assert_eq!(id, WRAP_ID);

    // do the stuff from replace-auth.sh
    personalize(client, WRAP_ID, out_dir)?;

    let shares = rusty_secrets::generate_shares(THRESHOLD, SHARES, &wrap_key)
        .with_context(|| {
        format!(
            "Failed to split secret into {} shares with threashold {}",
            SHARES, THRESHOLD
        )
    })?;

    println!(
        "WARNING: The wrap / backup key has been created and stored in the\n\
        YubiHSM. It will now be split into {} key shares and each share\n\
        will be individually written to {}. Before each keyshare is\n\
        printed, the operator will be prompted to ensure the appropriate key\n\
        custodian is present in front of the printer.\n\n\
        Press enter to begin the key share recording process ...",
        SHARES,
        print_dev.display(),
    );

    wait_for_line();

    let mut print_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(print_dev)?;

    for (i, share) in shares.iter().enumerate() {
        let share_num = i + 1;
        println!(
            "When key custodian {num} is ready, press enter to print share \
            {num}",
            num = share_num,
        );
        wait_for_line();

        print_file.write_all(format!("{}\n", share).as_bytes())?;
        println!(
            "When key custodian {} has collected their key share, press enter",
            share_num,
        );
        wait_for_line();
    }

    Ok(())
}

// consts for our authentication credential
const AUTH_DOMAINS: Domain = Domain::all();
const AUTH_CAPS: Capability = Capability::all();
const AUTH_DELEGATED: Capability = Capability::all();
const AUTH_ID: Id = 2;
const AUTH_LABEL: &str = "admin";

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
    let mut auth_wrap_path = out_dir.to_path_buf();
    auth_wrap_path.push(format!("{}.wrap.json", AUTH_LABEL));
    debug!("writing to: {}", auth_wrap_path.display());
    fs::write(&auth_wrap_path, msg_json)?;

    // dump cert for default attesation key in hsm
    debug!("extracting attestation certificate");
    let attest_cert = client.get_opaque(0)?;
    let mut attest_path = out_dir.to_path_buf();
    attest_path.push("hsm.attest.cert.pem");

    debug!("writing attestation cert to: {}", attest_path.display());
    fs::write(&attest_path, attest_cert)?;

    password.zeroize();

    Ok(())
}

/// This function is used when displaying key shares as a way for the user to
/// control progression through the key shares displayed in the terminal.
fn wait_for_line() {
    let _ = io::stdin().lines().next().unwrap().unwrap();
}

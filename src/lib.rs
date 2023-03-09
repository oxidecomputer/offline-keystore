// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use log::{debug, error};
use std::{fs, path::Path, str::FromStr};
use thiserror::Error;
use yubihsm::{
    authentication::{self, Key, DEFAULT_AUTHENTICATION_KEY_ID},
    object::{Id, Type},
    Capability, Client, Domain,
};
use zeroize::Zeroize;

pub mod config;

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

// consts for our authentication credential
const AUTH_DOMAINS: Domain = Domain::all();
const AUTH_CAPS: Capability = Capability::all();
const AUTH_DELEGATED: Capability = Capability::all();
const AUTH_ID: Id = 2;
const AUTH_LABEL: &str = "admin";

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

// create a new auth key, remove the default auth key, then export the new
// auth key under the wrap key with the provided id
pub fn personalize(client: &Client, wrap_id: Id, out_dir: &Path) -> Result<()> {
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

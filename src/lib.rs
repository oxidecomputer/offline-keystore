use anyhow::Result;
use log::{debug, error};
use std::{path::PathBuf, process::Command};
use thiserror::Error;
use yubihsm::{
    Capability, Client, Domain,
    object::Id,
    authentication::{self, Key},
};
use zeroize::Zeroize;

#[derive(Error, Debug)]
pub enum HsmError {
    #[error("your yubihms is broke")]
    Version,
}

const PASSWD_PROMPT: &str = "Enter new HSM password: ";
const PASSWD_PROMPT2: &str = "Enter password again to confirm: ";

// default password for YubiHSM2
const DEFAULT_AUTH_ID: &str = "1";

// consts for our authentication credential
const AUTH_DOMAINS: Domain = Domain::all();
const AUTH_CAPS: Capability = Capability::all();
const AUTH_DELEGATED: Capability = Capability::all();
const AUTH_ID: Id = 2;
const AUTH_LABEL: &str = "admin";

// create a new auth key, remove the default auth key, then export the new
// auth key under the wrap key with the provided id
pub fn personalize(
    client: &Client,
    wrap_id: Id,
    out_dir: &PathBuf,
) -> Result<()> {
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

    // delete the default auth key
    let mut cmd = Command::new("yubihsm-shell");
    cmd.arg("--action")
        .arg("delete-object")
        .arg("--password")
        .arg(&password)
        .arg("--authkey")
        .arg(AUTH_ID.to_string())
        .arg("--object-id")
        .arg(DEFAULT_AUTH_ID)
        .arg("--object-type")
        .arg("authentication-key");
    debug!("executing command: {:#?}", cmd);

    let output = cmd.output()?;
    if !output.status.success() {
        error!("failed to delete-object with status: {}", output.status);
        error!("stderr: \"{}\"", String::from_utf8_lossy(&output.stderr));
        return Err(HsmError::Version.into());
    }

    // backup new auth key using our wrap key to file
    let mut cmd = Command::new("yubihsm-shell");
    cmd.arg("--action")
        .arg("get-wrapped")
        .arg("--password")
        .arg(&password)
        .arg("--authkey")
        // this is an assumption based on the default auth having id 1 and
        // that we created our auth key before deleting the default one
        .arg("2")
        .arg("--wrap-id")
        .arg(wrap_id.to_string())
        .arg("--object-id")
        .arg("2") // backing up the same auth key we're using to authenticate
        .arg("--object-type")
        .arg("authentication-key")
        .arg("--out")
        .arg("auth.enc")
        .arg("--outformat")
        .arg("base64");
    debug!("executing command: {:#?}", cmd);

    let output = cmd.output()?;
    if !output.status.success() {
        error!("failed to get-wrapped auth with status: {}", output.status);
        error!("stderr: \"{}\"", String::from_utf8_lossy(&output.stderr));
        return Err(HsmError::Version.into());
    }

    password.zeroize();

    Ok(())
}

use anyhow::Result;
use log::{debug, error};
use std::{path::PathBuf, process::Command};
use thiserror::Error;
use yubihsm::object::Id;
use zeroize::Zeroize;

#[derive(Error, Debug)]
pub enum HsmError {
    #[error("your yubihms is broke")]
    Version,
}

const PASSWD_PROMPT: &str = "Enter new HSM password: ";
const PASSWD_PROMPT2: &str = "Enter same password again: ";

// default password for YubiHSM2
const DEFAULT_PASSWD: &str = "password";
const DEFAULT_AUTH_ID: &str = "1";

// consts for our authentication credential
const AUTH_DOMAINS: &str = "all";
const AUTH_CAPS: &str = "all";
const AUTH_DELEGATED: &str = "all";
const AUTH_ID: &str = "2";
const AUTH_LABEL: &str = "admin";

// create a new auth key, remove the default auth key, then export the new
// auth key under the wrap key with the provided id
pub fn personalize(wrap_id: Id, out_dir: &PathBuf) -> Result<()> {
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

    // create a new auth key
    let mut cmd = Command::new("yubihsm-shell");
    cmd.arg("--action")
        // this is 'put' instead of 'generate' because the YubiHSM derives
        // a key from the password that we provide. This is the same as us
        // using PBKDF2 to generate a key from the password, and then pushing
        // in the key.
        .arg("put-authentication-key")
        .arg("--password")
        .arg(DEFAULT_PASSWD)
        .arg("--authkey")
        .arg(DEFAULT_AUTH_ID)
        .arg("--object-id")
        .arg(AUTH_ID)
        .arg("--domains")
        .arg(AUTH_DOMAINS)
        .arg("--capabilities")
        .arg(AUTH_CAPS)
        .arg("--delegated")
        .arg(AUTH_DELEGATED)
        .arg("--label")
        .arg(AUTH_LABEL)
        .arg("--new-password")
        .arg(&password);
    debug!("executing command: {:#?}", cmd);

    let output = cmd.output()?;
    if !output.status.success() {
        error!("command failed with status: {}", output.status);
        error!("stderr: \"{}\"", String::from_utf8_lossy(&output.stderr));
        return Err(HsmError::Version.into());
    } else {
        debug!("command succeeded with output: {:#?}", output);
    }

    // delete the default auth key
    let mut cmd = Command::new("yubihsm-shell");
    cmd.arg("--action")
        .arg("delete-object")
        .arg("--password")
        .arg(&password)
        .arg("--authkey")
        .arg(AUTH_ID)
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

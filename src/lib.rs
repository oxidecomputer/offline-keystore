// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{Context, Result};
use fs_extra::dir::CopyOptions;
use hex::ToHex;
use log::{debug, error, info, warn};
use static_assertions as sa;
use std::{
    env,
    fs::{self, Permissions},
    io,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::Command,
    str::FromStr,
    thread,
    time::Duration,
};
use tempdir::TempDir;
use thiserror::Error;
use yubihsm::{
    authentication::{self, Key, DEFAULT_AUTHENTICATION_KEY_ID},
    object::{Id, Label, Type},
    wrap, Capability, Client, Domain,
};
use zeroize::Zeroize;

pub mod config;

use config::{KeySpec, Purpose};

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
    #[error("Invalid purpose for root CA key")]
    BadPurpose,
    #[error("failed to generate certificate")]
    CertGenFail,
    #[error("failed to create self signed cert for key")]
    SelfCertGenFail,
    #[error("your yubihms is broke")]
    Version,
}

const PASSWD_PROMPT: &str = "Enter new HSM password: ";
const PASSWD_PROMPT2: &str = "Enter password again to confirm: ";

/// Generate an asymmetric key from the provided specification.
pub fn generate(
    client: &Client,
    key_spec: &Path,
    wrap_id: Id,
    out_dir: &Path,
) -> Result<()> {
    let json = fs::read_to_string(key_spec)?;
    debug!("spec as json: {}", json);

    let spec = config::KeySpec::from_str(&json)?;
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
        wrap_id
    );
    let msg = client.export_wrapped(wrap_id, Type::AsymmetricKey, id)?;
    let msg_json = serde_json::to_string(&msg)?;

    debug!("exported asymmetric key: {:#?}", msg_json);

    let mut out_pathbuf = out_dir.to_path_buf();
    out_pathbuf.push(format!("{}.wrap.json", spec.label));

    debug!("writing to: {}", out_pathbuf.display());
    fs::write(out_pathbuf, msg_json)?;

    Ok(())
}

// NOTE: before using the pkcs11 engine the connector must be running:
// sudo systemctl start yubihsm-connector
macro_rules! openssl_cnf_fmt {
    () => {
        r#"
openssl_conf                = default_modules

[default_modules]
engines                     = engine_section
oid_section                 = OIDs

[engine_section]
pkcs11                      = pkcs11_section

[pkcs11_section]
engine_id                   = pkcs11
MODULE_PATH                 = /usr/lib/pkcs11/yubihsm_pkcs11.so
INIT_ARGS                   = connector=http://127.0.0.1:12345 debug
init                        = 0
# PIN format: "<auth key id><auth key password>"
# password must be 12 characters, 4 for the key id, 8 for the password
#PIN                         = "0001password"

[ ca ]
default_ca                  = CA_default

[ CA_default ]
dir                         = ./
crl_dir                     = $dir/crl
database                    = $dir/index.txt
new_certs_dir               = $dir/newcerts
certificate                 = $dir/ca.cert.pem
serial                      = $dir/serial
# key format:   <slot>:<key id>
private_key                 = 0:{key:#04}
name_opt                    = ca_default
cert_opt                    = ca_default
# certs may be retired, but they won't expire
default_enddate             = 99991231235959Z
default_crl_days            = 30
default_md                  = {hash:?}
preserve                    = no
policy                      = policy_match
email_in_dn                 = no
rand_serial                 = no
unique_subject              = yes

[ policy_match ]
countryName                 = optional
stateOrProvinceName         = optional
organizationName            = optional
organizationalUnitName      = optional
commonName                  = supplied
emailAddress                = optional

[ req ]
default_md                  = {hash:?}
string_mask                 = utf8only
default_enddate             = 99991231235959Z

[ v3_code_signing_prod_ca ]
subjectKeyIdentifier        = hash
authorityKeyIdentifier      = keyid:always,issuer
basicConstraints            = critical,CA:true
keyUsage                    = critical, keyCertSign, cRLSign

[ v3_code_signing_prod ]
subjectKeyIdentifier        = hash
authorityKeyIdentifier      = keyid:always,issuer
basicConstraints            = critical,CA:false
keyUsage                    = critical, digitalSignature

[ v3_code_signing_dev_ca ]
subjectKeyIdentifier        = hash
authorityKeyIdentifier      = keyid:always,issuer
basicConstraints            = critical,CA:true
keyUsage                    = critical, keyCertSign, cRLSign
certificatePolicies         = critical,development-device-only

[ v3_code_signing_dev ]
subjectKeyIdentifier        = hash
authorityKeyIdentifier      = keyid:always,issuer
basicConstraints            = critical,CA:false
keyUsage                    = critical, digitalSignature
certificatePolicies         = critical,development-device-only

[ v3_identity ]
subjectKeyIdentifier        = hash
authorityKeyIdentifier      = keyid:always,issuer
basicConstraints            = critical,CA:true
keyUsage                    = critical, keyCertSign, cRLSign

[ OIDs ]
development-device-only = 1.3.6.1.4.1.57551.1
"#
    };
}

pub fn ca_init(key_spec: &Path, ca_state: &Path, out: &Path) -> Result<()> {
    let json = fs::read_to_string(key_spec)?;
    debug!("spec as json: {}", json);

    let spec = config::KeySpec::from_str(&json)?;
    debug!("KeySpec from {}: {:#?}", key_spec.display(), spec);

    // sanity check: no signing keys at CA init
    // this makes me think we need different types for this:
    // one for the CA keys, one for the children we sign
    match spec.purpose {
        Purpose::ProductionCodeSigningCA
        | Purpose::DevelopmentCodeSigningCA
        | Purpose::Identity => (),
        _ => return Err(HsmError::BadPurpose.into()),
    }

    let pwd = std::env::current_dir()?;
    debug!("got current directory: {:?}", pwd);

    // setup CA directory structure
    let label = spec.label.to_string();
    let ca_dir = ca_state.join(&label);
    info!("bootstrapping CA files in: {}", ca_dir.display());
    fs::create_dir(&ca_dir)?;
    debug!("setting current directory: {}", ca_dir.display());
    std::env::set_current_dir(&ca_dir)?;

    // copy the key spec file to the ca state dir
    fs::write("key.spec", json)?;

    bootstrap_ca(&spec)?;

    debug!("starting connector");
    let mut connector = Command::new("yubihsm-connector").spawn()?;

    debug!("connector started");
    thread::sleep(Duration::from_millis(1000));

    // We're chdir-ing around and that makes it a PITA to keep track of file
    // paths. Stashing everything in a tempdir make it easier to copy it all
    // out when we're done.
    let tmp_dir = TempDir::new("ca-init")?;
    let csr = tmp_dir.path().join(format!("{}.csr.pem", label));

    let mut cmd = Command::new("openssl");
    let output = cmd
        .arg("req")
        .arg("-config")
        .arg("openssl.cnf")
        .arg("-new")
        .arg("-subj")
        .arg(format!("/CN={}/", spec.common_name))
        .arg("-engine")
        .arg("pkcs11")
        .arg("-keyform")
        .arg("engine")
        .arg("-key")
        .arg(format!("0:{:#04}", spec.id))
        .arg("-out")
        .arg(&csr)
        .output()?;

    info!("executing command: \"{:#?}\"", cmd);

    if !output.status.success() {
        warn!("command failed with status: {}", output.status);
        warn!("stderr: \"{}\"", String::from_utf8_lossy(&output.stderr));
        connector.kill()?;
        return Err(HsmError::SelfCertGenFail.into());
    }

    //  generate cert for CA root
    //  select v3 extensions from ... key spec?
    let mut cmd = Command::new("openssl");
    let output = cmd
        .arg("ca")
        .arg("-batch")
        .arg("-selfsign")
        .arg("-config")
        .arg("openssl.cnf")
        .arg("-engine")
        .arg("pkcs11")
        .arg("-keyform")
        .arg("engine")
        .arg("-keyfile")
        .arg(format!("0:{:#04}", spec.id))
        .arg("-extensions")
        .arg(spec.purpose.to_string())
        .arg("-in")
        .arg(&csr)
        .arg("-out")
        .arg("ca.cert.pem")
        .output()?;

    info!("executing command: \"{:#?}\"", cmd);

    if !output.status.success() {
        warn!("command failed with status: {}", output.status);
        warn!("stderr: \"{}\"", String::from_utf8_lossy(&output.stderr));
        connector.kill()?;
        return Err(HsmError::SelfCertGenFail.into());
    }

    connector.kill()?;

    let cert = tmp_dir.path().join(format!("{}.cert.pem", label));
    fs::copy("ca.cert.pem", cert)?;

    env::set_current_dir(pwd)?;

    // copy contents of temp directory to out
    debug!("tmpdir: {:?}", tmp_dir);
    let paths = fs::read_dir(tmp_dir.path())?
        .map(|res| res.map(|e| e.path()))
        .collect::<Result<Vec<_>, io::Error>>()?;
    let opts = CopyOptions::default().overwrite(true);
    fs_extra::move_items(&paths, out, &opts)?;

    Ok(())
}

pub fn ca_sign(
    key_spec: &Path,
    csr: &Path,
    state: &Path,
    publish: &Path,
) -> Result<()> {
    // deserialize spec file
    let json = fs::read_to_string(key_spec)?;
    debug!("spec as json: {}", json);

    let spec = config::KeySpec::from_str(&json)?;
    debug!("KeySpec from {}: {:#?}", key_spec.display(), spec);

    // sanity check: no signing keys at CA init
    // this makes me think we need different types for this:
    // one for the CA keys, one for the children we sign
    match spec.purpose {
        Purpose::ProductionCodeSigning
        | Purpose::DevelopmentCodeSigning
        | Purpose::Identity => (),
        _ => return Err(HsmError::BadPurpose.into()),
    }

    // get canonical path to CSR before chdir into CA dir
    let csr = fs::canonicalize(csr)?;
    debug!("canonical CSR: {}", csr.display());
    let publish = fs::canonicalize(publish)?;
    debug!("canonical publish: {}", publish.display());

    // pushd into ca dir based on spec file
    let pwd = std::env::current_dir()?;
    debug!("got current directory: {:?}", pwd);

    let ca_dir = state.join(spec.label.to_string());
    std::env::set_current_dir(&ca_dir)?;
    debug!("setting current directory: {}", ca_dir.display());

    // start connector
    debug!("starting connector");
    let mut connector = Command::new("yubihsm-connector").spawn()?;

    debug!("connector started");
    std::thread::sleep(std::time::Duration::from_millis(1000));

    // cert file name takes prefix from CSR file name, appends ".cert.pem"
    debug!("canonical csr: {}", csr.display());
    let csr_filename = csr
        .file_name()
        .unwrap()
        .to_os_string()
        .into_string()
        .unwrap();
    let csr_prefix = match csr_filename.find('.') {
        Some(i) => csr_filename[..i].to_string(),
        None => csr_filename,
    };
    let cert = publish.join(format!("{}.cert.pem", csr_prefix));

    // execute CA command
    let mut cmd = Command::new("openssl");
    cmd.arg("ca")
        .arg("-batch")
        .arg("-config")
        .arg("openssl.cnf")
        .arg("-engine")
        .arg("pkcs11")
        .arg("-keyform")
        .arg("engine")
        .arg("-keyfile")
        .arg(format!("0:{:#04}", spec.id))
        .arg("-extensions")
        .arg(spec.purpose.to_string())
        .arg("-in")
        .arg(&csr)
        .arg("-out")
        .arg(&cert);

    info!("executing command: \"{:#?}\"", cmd);
    let output = cmd.output()?;

    if !output.status.success() {
        warn!("command failed with status: {}", output.status);
        warn!("stderr: \"{}\"", String::from_utf8_lossy(&output.stderr));
        connector.kill()?;
        return Err(HsmError::CertGenFail.into());
    }

    // kill connector
    connector.kill()?;

    std::env::set_current_dir(pwd)?;

    Ok(())
}

/// Create the directory structure and initial files expected by the `openssl ca` tool.
fn bootstrap_ca(key_spec: &KeySpec) -> Result<()> {
    // create directories expected by `openssl ca`: crl, newcerts
    for dir in ["crl", "newcerts"] {
        debug!("creating directory: {}?", dir);
        fs::create_dir(dir)?;
    }

    // the 'private' directory is a special case w/ restricted permissions
    let priv_dir = "private";
    debug!("creating directory: {}?", priv_dir);
    fs::create_dir(priv_dir)?;
    let perms = Permissions::from_mode(0o700);
    debug!(
        "setting permissions on directory {} to {:#?}",
        priv_dir, perms
    );
    fs::set_permissions(priv_dir, perms)?;

    // touch 'index.txt' file
    use std::fs::OpenOptions;
    let index = "index.txt";
    debug!("touching file {}", index);
    OpenOptions::new().create(true).write(true).open(index)?;

    // write initial serial number to 'serial' (echo 1000 > serial)
    let serial = "serial";
    let sn = 1000u32;
    debug!(
        "setting initial serial number to \"{}\" in file \"{}\"",
        sn, serial
    );
    fs::write(serial, sn.to_string())?;

    // create & write out an openssl.cnf
    fs::write(
        "openssl.cnf",
        format!(openssl_cnf_fmt!(), key = key_spec.id, hash = key_spec.hash),
    )?;

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
pub fn initialize(client: &Client, out_dir: &Path) -> Result<()> {
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

    // do the stuff from replace-auth.sh
    personalize(client, id, out_dir)?;

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
    out_dir.push(format!("{}.wrap.json", AUTH_LABEL));

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

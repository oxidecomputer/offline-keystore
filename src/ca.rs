// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use fs_extra::dir::CopyOptions;
use log::{debug, error, info, warn};
use std::{
    env,
    fs::{self, OpenOptions, Permissions},
    io,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::Command,
    str::FromStr,
    thread,
    time::Duration,
};
use tempfile::TempDir;
use thiserror::Error;

use crate::config::{self, CsrSpec, KeySpec, Purpose, KEYSPEC_EXT};

/// Name of file in root of a CA directory with key spec used to generate key
/// in HSM.
const CA_KEY_SPEC: &str = "key.spec";

const CSRSPEC_EXT: &str = ".csrspec.json";

#[derive(Error, Debug)]
pub enum CaError {
    #[error("Invalid purpose for root CA key")]
    BadPurpose,
    #[error("path not a directory")]
    BadSpecDirectory,
    #[error("failed to generate certificate")]
    CertGenFail,
    #[error("failed to create self signed cert for key")]
    SelfCertGenFail,
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
MODULE_PATH                 = {pkcs11_path}
INIT_ARGS                   = connector=http://127.0.0.1:12345 debug
init                        = 0

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
private_key                 = 0:{key:04x}
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

/// Get password for pkcs11 operations to keep the user from having to enter
/// the password multiple times (once for signing the CSR, one for signing
/// the cert). We also prefix the password with '0002' so the YubiHSM
/// PKCS#11 module knows which key to use
fn passwd_to_env(env_str: &str) -> Result<()> {
    let mut password = "0002".to_string();
    password.push_str(&rpassword::prompt_password("Enter YubiHSM Password: ")?);
    std::env::set_var(env_str, password);

    Ok(())
}

/// Initialize an openssl CA directory & self signed cert for the provided
/// KeySpec.
/// NOTE: The YubiHSM supports 16 sessions and stale sessions are recycled
/// after 30 seconds of inactivity. Depending on however many KeySpecs we're
/// processing tests shows that we run out of sessions pretty quickly. This
/// is likely caused by the pkcs11 module not cleaning up after itself. To
/// account for this we sleep between invocations of the openssl tools to give
/// the stale sessions time to be reclaimed by the HSM.
pub fn initialize(
    key_spec: &Path,
    pkcs11_path: &Path,
    ca_state: &Path,
    out: &Path,
) -> Result<()> {
    let key_spec = fs::canonicalize(key_spec)?;
    debug!("canonical KeySpec path: {}", key_spec.display());

    let paths = if key_spec.is_file() {
        vec![key_spec.clone()]
    } else {
        config::files_with_ext(&key_spec, KEYSPEC_EXT)?
    };

    if paths.is_empty() {
        return Err(anyhow::anyhow!(
            "no files with extension \"{}\" found in dir: {}",
            KEYSPEC_EXT,
            &key_spec.display()
        ));
    }

    // start connector
    debug!("starting connector");
    let mut connector = Command::new("yubihsm-connector").spawn()?;

    debug!("connector started");

    passwd_to_env("OKM_HSM_PKCS11_AUTH")?;

    let tmp_dir = TempDir::new()?;
    for path in paths {
        info!("Initializing CA from KeySpec: {:?}", path);
        // sleep to let sessions cycle
        thread::sleep(Duration::from_millis(1500));
        if let Err(e) =
            initialize_keyspec(&path, pkcs11_path, &tmp_dir, ca_state, out)
        {
            // Ignore possible error from killing connector because we already
            // have an error to report and it'll be more interesting.
            let _ = connector.kill();
            return Err(e);
        }
    }

    connector.kill()?;

    Ok(())
}

fn initialize_keyspec(
    key_spec: &Path,
    pkcs11_path: &Path,
    tmp_dir: &TempDir,
    ca_state: &Path,
    out: &Path,
) -> Result<()> {
    let json = fs::read_to_string(key_spec)?;
    debug!("spec as json: {}", json);

    let spec = KeySpec::from_str(&json)?;
    debug!("KeySpec from {}: {:#?}", key_spec.display(), spec);

    // sanity check: no signing keys at CA init
    // this makes me think we need different types for this:
    // one for the CA keys, one for the children we sign
    match spec.purpose {
        Purpose::ProductionCodeSigningCA
        | Purpose::DevelopmentCodeSigningCA
        | Purpose::Identity => (),
        _ => return Err(CaError::BadPurpose.into()),
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

    bootstrap_ca(&spec, pkcs11_path)?;

    // We're chdir-ing around and that makes it a PITA to keep track of file
    // paths. Stashing everything in a tempdir make it easier to copy it all
    // out when we're done.
    let csr = tmp_dir.path().join(format!("{}.csr.pem", label));

    // sleep to let sessions cycle
    thread::sleep(Duration::from_millis(1500));

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
        .arg(format!("0:{:04x}", spec.id))
        .arg("-passin")
        .arg("env:OKM_HSM_PKCS11_AUTH")
        .arg("-out")
        .arg(&csr)
        .output()?;

    info!("executing command: \"{:#?}\"", cmd);

    if !output.status.success() {
        warn!("command failed with status: {}", output.status);
        warn!("stderr: \"{}\"", String::from_utf8_lossy(&output.stderr));
        return Err(CaError::SelfCertGenFail.into());
    }

    // sleep to let sessions cycle
    thread::sleep(Duration::from_millis(1500));

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
        .arg(format!("0:{:04x}", spec.id))
        .arg("-extensions")
        .arg(spec.purpose.to_string())
        .arg("-passin")
        .arg("env:OKM_HSM_PKCS11_AUTH")
        .arg("-in")
        .arg(&csr)
        .arg("-out")
        .arg("ca.cert.pem")
        .output()?;

    info!("executing command: \"{:#?}\"", cmd);

    if !output.status.success() {
        warn!("command failed with status: {}", output.status);
        warn!("stderr: \"{}\"", String::from_utf8_lossy(&output.stderr));
        return Err(CaError::SelfCertGenFail.into());
    }

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

pub fn sign(csr_spec_path: &Path, state: &Path, publish: &Path) -> Result<()> {
    let csr_spec_path = fs::canonicalize(csr_spec_path)?;
    debug!("canonical CsrSpec path: {}", csr_spec_path.display());

    let paths = if csr_spec_path.is_file() {
        vec![csr_spec_path]
    } else {
        config::files_with_ext(&csr_spec_path, CSRSPEC_EXT)?
    };

    // start connector
    debug!("starting connector");
    let mut connector = Command::new("yubihsm-connector").spawn()?;

    debug!("connector started");
    std::thread::sleep(std::time::Duration::from_millis(1000));

    passwd_to_env("OKM_HSM_PKCS11_AUTH")?;

    let tmp_dir = TempDir::new()?;
    for path in paths {
        // process csr spec
        info!("Signing CSR from spec: {:?}", path);
        if let Err(e) = sign_csrspec(&path, &tmp_dir, state, publish) {
            // Ignore possible error from killing connector because we already
            // have an error to report and it'll be more interesting.
            let _ = connector.kill();
            return Err(e);
        }
    }

    // kill connector
    connector.kill()?;

    Ok(())
}

pub fn sign_csrspec(
    csr_spec_path: &Path,
    tmp_dir: &TempDir,
    state: &Path,
    publish: &Path,
) -> Result<()> {
    // deserialize the csrspec
    debug!("Getting CSR spec from: {}", csr_spec_path.display());
    let json = fs::read_to_string(csr_spec_path)?;
    debug!("spec as json: {}", json);

    let csr_spec = CsrSpec::from_str(&json)?;
    debug!("CsrSpec: {:#?}", csr_spec);

    // get the label
    // use label to reconstruct path to CA root dir for key w/ label
    let key_spec = state.join(csr_spec.label.to_string()).join(CA_KEY_SPEC);

    debug!("Getting KeySpec from: {}", key_spec.display());
    let json = fs::read_to_string(key_spec)?;
    debug!("spec as json: {}", json);

    let key_spec = KeySpec::from_str(&json)?;
    debug!("KeySpec: {:#?}", key_spec);

    // sanity check: no signing keys at CA init
    // this makes me think we need different types for this:
    // one for the CA keys, one for the children we sign
    // map purpose of CA key to key associated with CSR
    let purpose = match key_spec.purpose {
        Purpose::ProductionCodeSigningCA => Purpose::ProductionCodeSigning,
        Purpose::DevelopmentCodeSigningCA => Purpose::DevelopmentCodeSigning,
        Purpose::Identity => Purpose::Identity,
        _ => return Err(CaError::BadPurpose.into()),
    };

    let publish = fs::canonicalize(publish)?;
    debug!("canonical publish: {}", publish.display());

    // pushd into ca dir based on spec file
    let pwd = std::env::current_dir()?;
    debug!("got current directory: {:?}", pwd);

    let ca_dir = state.join(key_spec.label.to_string());
    std::env::set_current_dir(&ca_dir)?;
    debug!("setting current directory: {}", ca_dir.display());

    // Get prefix from CsrSpec file. We us this to generate file names for the
    // temp CSR file and the output cert file.
    let csr_filename = csr_spec_path
        .file_name()
        .unwrap()
        .to_os_string()
        .into_string()
        .unwrap();
    let csr_prefix = match csr_filename.find('.') {
        Some(i) => csr_filename[..i].to_string(),
        None => csr_filename,
    };

    // create a tempdir & write CSR there for openssl: AFAIK the `ca` command
    // won't take the CSR over stdin
    let tmp_csr = tmp_dir.path().join(format!("{}.csr.pem", csr_prefix));
    debug!("writing CSR to: {}", tmp_csr.display());
    fs::write(&tmp_csr, &csr_spec.csr)?;

    let cert = publish.join(format!("{}.cert.pem", csr_prefix));
    debug!("writing cert to: {}", cert.display());

    // sleep to let sessions cycle
    thread::sleep(Duration::from_millis(2500));

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
        .arg(format!("0:{:04x}", key_spec.id))
        .arg("-extensions")
        .arg(purpose.to_string())
        .arg("-passin")
        .arg("env:OKM_HSM_PKCS11_AUTH")
        .arg("-in")
        .arg(&tmp_csr)
        .arg("-out")
        .arg(&cert);

    info!("executing command: \"{:#?}\"", cmd);
    let output = cmd.output()?;

    if !output.status.success() {
        warn!("command failed with status: {}", output.status);
        warn!("stderr: \"{}\"", String::from_utf8_lossy(&output.stderr));
        return Err(CaError::CertGenFail.into());
    }

    std::env::set_current_dir(pwd)?;

    Ok(())
}

/// Create the directory structure and initial files expected by the `openssl ca` tool.
fn bootstrap_ca(key_spec: &KeySpec, pkcs11_path: &Path) -> Result<()> {
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
        format!(
            openssl_cnf_fmt!(),
            key = key_spec.id,
            hash = key_spec.hash,
            pkcs11_path = pkcs11_path.display()
        ),
    )?;

    Ok(())
}

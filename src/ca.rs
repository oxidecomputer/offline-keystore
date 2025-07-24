// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{anyhow, Context, Result};
use hex::ToHex;
use log::{debug, error, info, warn};
use rsa::{pkcs1::EncodeRsaPublicKey, RsaPublicKey};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    env,
    fs::{self, OpenOptions, Permissions},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    str::FromStr,
    thread,
    time::Duration,
};
use tempfile::NamedTempFile;
use thiserror::Error;
use x509_cert::{certificate::Certificate, der::DecodePem};
use yubihsm::Client;
use zeroize::Zeroizing;

use crate::config::{CsrSpec, DcsrSpec, KeySpec, Purpose, DCSR_EXT};

/// Name of file in root of a CA directory with key spec used to generate key
/// in HSM.
const CA_KEY_SPEC: &str = "key.spec";

/// Name of file in root of a CA directory containing the CA's own certificate.
const CA_CERT: &str = "ca.cert.pem";

// Name of the environment variable to get the YubiHSM auth id and password
// into the PKCS#11 module, the format is "<auth-id>:<passwd>" where
// `auth-id` is a 4 digit decimal number and `password` is a string. We use
// a second variable to accommodate the `auth-id`.
pub const ENV_CA_PASSWORD: &str = "OKM_HSM_PKCS11_AUTH";

#[derive(Error, Debug)]
pub enum CaError {
    #[error("Invalid path to CsrSpec file")]
    BadCsrSpecPath,
    #[error("Invalid path to DcsrSpec file")]
    BadDcsrSpecPath,
    #[error("Invalid path to KeySpec file")]
    BadKeySpecPath,
    #[error("Invalid purpose for root CA key")]
    BadPurpose,
    #[error("path not a directory")]
    BadSpecDirectory,
    #[error("failed to generate certificate")]
    CertGenFail,
    #[error("failed to create self signed cert for key")]
    SelfCertGenFail,
    #[error("CA state directory has no key.spec")]
    NoKeySpec,
}

// This is a template for the openssl config file used for all CAs.
// In this template we populate 3 fields:
// - `pkcs11_path`: This is the path to the PKCS#11 module used by `openssl`
//   to communicate w/ the YubiHSM / connector.
// - `key`: This is the Id of the key stored in the YubiHSM. It is an integer
//   and will be prefixed by 0's.
// - `hash`: This is the default digest function used when signing.
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
# add 'debug' to INIT_ARGS
INIT_ARGS                   = connector=http://127.0.0.1:12345
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
# Setting rand_serial to _any_ value, including "no", enables that option
#rand_serial                = yes
unique_subject              = no

[ policy_match ]
countryName                 = supplied
stateOrProvinceName         = optional
organizationName            = supplied
organizationalUnitName      = optional
commonName                  = supplied
emailAddress                = optional

[ req ]
default_md                  = {hash:?}
string_mask                 = utf8only

[ v3_rot_release_root ]
subjectKeyIdentifier        = hash
authorityKeyIdentifier      = keyid:always,issuer
basicConstraints            = critical,CA:true
keyUsage                    = critical, keyCertSign, cRLSign
extendedKeyUsage            = nxpLpc55DebugAuthCredentialSigning
certificatePolicies         = rotCodeSigningReleasePolicy

[ v3_code_signing_rel ]
subjectKeyIdentifier        = hash
authorityKeyIdentifier      = keyid:always,issuer
basicConstraints            = critical,CA:false
keyUsage                    = critical, digitalSignature
extendedKeyUsage            = codeSigning
certificatePolicies         = rotCodeSigningReleasePolicy

[ v3_rot_development_root ]
subjectKeyIdentifier        = hash
authorityKeyIdentifier      = keyid:always,issuer
basicConstraints            = critical,CA:true
keyUsage                    = critical, keyCertSign, cRLSign
extendedKeyUsage            = nxpLpc55DebugAuthCredentialSigning
certificatePolicies         = rotCodeSigningDevelopmentPolicy

[ v3_code_signing_dev ]
subjectKeyIdentifier        = hash
authorityKeyIdentifier      = keyid:always,issuer
basicConstraints            = critical,CA:false
keyUsage                    = critical, digitalSignature
extendedKeyUsage            = codeSigning
certificatePolicies         = rotCodeSigningDevelopmentPolicy

[ v3_identity ]
subjectKeyIdentifier        = hash
authorityKeyIdentifier      = keyid:always,issuer
basicConstraints            = critical,CA:true
keyUsage                    = critical, keyCertSign, cRLSign
certificatePolicies         = critical, deviceIdentityPolicy, tcg-dice-kp-identityInit, tcg-dice-kp-attestInit, tcg-dice-kp-eca

[ OIDs ]
# https://github.com/oxidecomputer/oana#asn1-object-identifiers
rotCodeSigningReleasePolicy = 1.3.6.1.4.1.57551.1.1
rotCodeSigningDevelopmentPolicy = 1.3.6.1.4.1.57551.1.2
deviceIdentityPolicy = 1.3.6.1.4.1.57551.1.3
nxpLpc55DebugAuthCredentialSigning = 1.3.6.1.4.1.57551.2.1
tcg-dice-kp-identityInit = 2.23.133.5.4.100.6
tcg-dice-kp-attestInit = 2.23.133.5.4.100.8
tcg-dice-kp-eca = 2.23.133.5.4.100.12

"#
    };
}

/// Get password for pkcs11 operations to keep the user from having to enter
/// the password multiple times (once for signing the CSR, one for signing
/// the cert). We also prefix the password with '0002' so the YubiHSM
/// PKCS#11 module knows which key to use
fn passwd_to_env(env_str: &str, password: &Zeroizing<String>) -> Result<()> {
    use std::ops::Deref;

    let password = Zeroizing::new(format!("0002{}", password.deref()));
    std::env::set_var(env_str, password);

    Ok(())
}

/// Start the yubihsm-connector process.
/// NOTE: The connector dumps ~10 lines of text for each command.
/// We can increase verbosity with the `-debug` flag, but the only way
/// we can dial this down is by sending stderr to /dev/null.
fn start_connector() -> Result<Child> {
    debug!("starting connector");
    let child = Command::new("yubihsm-connector")
        .stderr(Stdio::null())
        .stdout(Stdio::null())
        .spawn()?;

    // Sleep for a second to allow the connector to start before we start
    // sending commands to it.
    std::thread::sleep(std::time::Duration::from_millis(1000));

    Ok(child)
}

/// Functions that may return either a PEM encoded cert or CSR do so using
/// this enum.
pub enum CertOrCsr {
    Cert(String),
    Csr(String),
}

pub struct DacStore {
    root: PathBuf,
}

impl DacStore {
    fn pubkey_to_digest(pubkey: &RsaPublicKey) -> Result<String> {
        // calculate sha256(pub_key) where pub_key is the DER encoded RSA key
        let der = pubkey
            .to_pkcs1_der()
            .context("Encode RSA public key as DER")?;

        let mut digest = Sha256::new();
        digest.update(der.as_bytes());
        let digest = digest.finalize();

        Ok(digest.encode_hex::<String>())
    }

    fn pubkey_to_dcsr_path(&self, pubkey: &RsaPublicKey) -> Result<PathBuf> {
        let digest = Self::pubkey_to_digest(pubkey)?;

        Ok(self.root.as_path().join(format!("{digest}.{DCSR_EXT}")))
    }

    pub fn new<P: AsRef<Path>>(root: P) -> Result<Self> {
        // check that the path provided exists
        let metadata = fs::metadata(root.as_ref()).with_context(|| {
            format!(
                "Getting metadata for DacStore root: {}",
                root.as_ref().display()
            )
        })?;

        // - is a directory
        if !metadata.is_dir() {
            return Err(anyhow!("DacStore root is not a directory"));
        }

        // - we have write access to it
        if metadata.permissions().readonly() {
            return Err(anyhow!("DacStore directory is not writable"));
        }

        Ok(Self {
            root: PathBuf::from(root.as_ref()),
        })
    }

    pub fn add(&self, pubkey: &RsaPublicKey, dcsr: &[u8]) -> Result<()> {
        // Make sure we haven't already issued a DCSR for this key before
        // we save it to disk. The caller should perform this check before
        // signing the DCSR but we do it here also to keep from overwriting
        // an existing one.
        if let Some(path) = self.find(pubkey)? {
            return Err(anyhow!(
                "DCSR for public key exists: {}",
                path.display()
            ));
        }

        let path = self.pubkey_to_dcsr_path(pubkey)?;

        fs::write(&path, dcsr)
            .context(format!("Writing DCSR to destination {}", path.display()))
    }

    pub fn find(&self, pubkey: &RsaPublicKey) -> Result<Option<PathBuf>> {
        let path = self.pubkey_to_dcsr_path(pubkey)?;

        if fs::exists(&path).with_context(|| {
            format!("Checking for the existance of {}", path.display())
        })? {
            Ok(Some(path))
        } else {
            Ok(None)
        }
    }
}

/// The `Ca` type represents the collection of files / metadata that is a
/// certificate authority.
pub struct Ca {
    root: PathBuf,
    spec: KeySpec,
    dacs: DacStore,
}

impl Ca {
    /// Create a Ca instance from a directory. This directory must be the
    /// root of a previously initialized Ca.
    pub fn load<P: AsRef<Path>>(root: P, dacs: DacStore) -> Result<Self> {
        let root = PathBuf::from(root.as_ref());

        let spec = root.join(CA_KEY_SPEC);
        if !spec.exists() {
            return Err(CaError::NoKeySpec.into());
        }

        let spec = fs::read_to_string(spec)?;
        let spec = KeySpec::from_str(spec.as_ref())?;

        Ok(Self { root, spec, dacs })
    }

    /// Get the name of the CA in `String` form. A `Ca`s name comes from the
    /// key spec file and *should* correspond to the label for the associated
    /// key in the YubiHSM.
    pub fn name(&self) -> String {
        self.spec.label.to_string()
    }

    /// Get an `x509_cert::certificate::Certificate` for the `Ca`s
    /// certificate.
    pub fn cert(&self) -> Result<Certificate> {
        let bytes = fs::read(self.root.join(CA_CERT))?;
        Ok(Certificate::from_pem(bytes)?)
    }

    /// Create a new CA instance under `root` & initialize its metadata
    /// according to the provided keyspec. The `pkcs11_lib` is inserted into
    /// the generated openssl.cnf so openssl can find it. If the keyspec
    /// defines a root / selfsigned CA then the self signed cert will be
    /// written to the output path w/ name `$label.cert.pem`. If not then we
    /// create a CSR named `$label.csr.pem` instead.
    pub fn initialize<P: AsRef<Path>>(
        spec: &KeySpec,
        root: P,
        pkcs11_lib: P,
        password: &Zeroizing<String>,
    ) -> Result<CertOrCsr> {
        match spec.purpose {
            Purpose::RoTReleaseRoot
            | Purpose::RoTDevelopmentRoot
            | Purpose::Identity => (),
            _ => return Err(CaError::BadPurpose.into()),
        }

        bootstrap_ca_dir(spec, root.as_ref(), pkcs11_lib.as_ref())?;

        // save current pwd so we can return to where we started
        let pwd = env::current_dir()?;
        // chdir into `Ca` root directory: openssl.cnf has relative paths
        env::set_current_dir(&root)?;

        // the connector must be running for the PKCS#11 module to work
        let connector = start_connector()?;
        // the PKCS#11 module gets the auth value for the YubiHSM from the
        // environment
        passwd_to_env(ENV_CA_PASSWORD, password)?;

        let csr = NamedTempFile::new()?;

        let mut cmd = Command::new("openssl");
        cmd.arg("req")
            .arg("-config")
            .arg("openssl.cnf")
            .arg("-new")
            .arg("-subj")
            .arg(format!(
                "/C=US/O=Oxide Computer Company/CN={}/",
                spec.common_name
            ))
            .arg("-engine")
            .arg("pkcs11")
            .arg("-keyform")
            .arg("engine")
            .arg("-key")
            .arg(format!("0:{:04x}", spec.id))
            .arg("-passin")
            .arg(format!("env:{ENV_CA_PASSWORD}"))
            .arg("-out")
            .arg(csr.path());

        debug!("executing command: \"{:#?}\"", cmd);
        let output = match cmd.output() {
            Ok(o) => o,
            Err(e) => {
                teardown_warn_only(connector, pwd);
                return Err(e.into());
            }
        };

        if !output.status.success() {
            warn!("command failed with status: {}", output.status);
            warn!("stderr: \"{}\"", String::from_utf8_lossy(&output.stderr));
            teardown_warn_only(connector, pwd);
            return Err(CaError::SelfCertGenFail.into());
        }

        // return the path to the artifact created
        // if the spec defines a self signed / root cert we'll generate the
        // cert and return a path to it
        // else we'll get back the path to the CSR so that it can be exported
        // and eventually certified by some external process
        let pem = if spec.self_signed {
            // sleep to let sessions cycle
            thread::sleep(Duration::from_millis(1500));

            info!("Generating self-signed cert for CA root");
            let mut cmd = Command::new("openssl");
            cmd.arg("ca")
                .arg("-batch")
                .arg("-selfsign")
                .arg("-notext")
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
                .arg(csr.path())
                .arg("-out")
                .arg(CA_CERT)
                .output()?;

            debug!("executing command: \"{:#?}\"", cmd);
            let output = match cmd
                .output()
                .context("Failed to self sign cert with `openssl ca`")
            {
                Ok(o) => o,
                Err(e) => {
                    teardown_warn_only(connector, pwd);
                    return Err(e);
                }
            };

            if !output.status.success() {
                warn!("command failed with status: {}", output.status);
                warn!(
                    "stderr: \"{}\"",
                    String::from_utf8_lossy(&output.stderr)
                );
                teardown_warn_only(connector, pwd);
                return Err(CaError::SelfCertGenFail.into());
            }

            let cert_pem =
                fs::read_to_string(root.as_ref().to_path_buf().join(CA_CERT))?;
            CertOrCsr::Cert(cert_pem)
        } else {
            // self-signed=false in keyspec indicates that the CA being
            // initialized is an intermediate: someone else has to certify it
            // so we copy the CSR to output
            let csr_pem = fs::read_to_string(csr.path())?;
            CertOrCsr::Csr(csr_pem)
        };

        teardown_warn_only(connector, pwd);
        Ok(pem)
    }

    /// Sign the CSR from the provided CsrSpec. The cert produced is returned
    /// as a PEM encoded x509 cert.
    pub fn sign_csrspec(
        &self,
        spec: &CsrSpec,
        password: &Zeroizing<String>,
    ) -> Result<Vec<u8>> {
        // map purpose of CA key to key associated with CSR
        // this is awkward and should be revisited
        let purpose = match self.spec.purpose {
            Purpose::RoTReleaseRoot => Purpose::RoTReleaseCodeSigning,
            Purpose::RoTDevelopmentRoot => Purpose::RoTDevelopmentCodeSigning,
            Purpose::Identity => Purpose::Identity,
            _ => return Err(CaError::BadPurpose.into()),
        };

        // chdir to CA state directory as required to run `openssl ca`
        let pwd = std::env::current_dir()?;
        std::env::set_current_dir(&self.root)?;

        // create a tempdir & write CSR there for openssl: AFAIK the `ca` command
        // won't take the CSR over stdin
        let csr = NamedTempFile::new()?;
        debug!("writing CSR to: {}", csr.path().display());
        fs::write(&csr, &spec.csr)?;

        // sleep to let sessions cycle
        thread::sleep(Duration::from_millis(2500));

        info!(
            "Generating cert from CSR & signing with key: {}",
            self.name()
        );

        let cert = NamedTempFile::new()?;

        let connector = start_connector()?;
        passwd_to_env(ENV_CA_PASSWORD, password)?;

        let mut cmd = Command::new("openssl");
        cmd.arg("ca")
            .arg("-batch")
            .arg("-notext")
            .arg("-config")
            .arg("openssl.cnf")
            .arg("-engine")
            .arg("pkcs11")
            .arg("-keyform")
            .arg("engine")
            .arg("-keyfile")
            .arg(format!("0:{:04x}", self.spec.id))
            .arg("-extensions")
            .arg(purpose.to_string())
            .arg("-passin")
            .arg(format!("env:{ENV_CA_PASSWORD}"))
            .arg("-in")
            .arg(csr.path())
            .arg("-out")
            .arg(cert.path());

        debug!("executing command: \"{:#?}\"", cmd);
        let output = match cmd.output() {
            Ok(o) => o,
            Err(e) => {
                teardown_warn_only(connector, pwd);
                return Err(e.into());
            }
        };

        if !output.status.success() {
            warn!("command failed with status: {}", output.status);
            warn!("stderr: \"{}\"", String::from_utf8_lossy(&output.stderr));
            teardown_warn_only(connector, pwd);
            return Err(CaError::CertGenFail.into());
        } else {
            debug!(
                "Successfully signed CsrSpec \"{}\" producing cert \"{}\"",
                csr.path().display(),
                cert.path().display()
            );
        }

        teardown_warn_only(connector, pwd);
        fs::read(cert.path()).with_context(|| {
            format!("failed to read file {}", cert.as_ref().display())
        })
    }

    /// Sign the debug credential signing request from the provided DcsrSpec.
    /// This function uses the provided HashMap to find the `Ca`s whose public
    /// keys are to be included in the debug credential.
    pub fn sign_dcsrspec(
        &self,
        spec: DcsrSpec,
        cas: &HashMap<String, Ca>,
        client: &Client,
    ) -> Result<Vec<u8>> {
        debug!("signing DcsrSpec: {:?}", spec);
        if let Some(dcsr) = self
            .dacs
            .find(&spec.dcsr.debug_public_key)
            .context("Looking up DCSR for pubkey")?
        {
            return Err(anyhow!(
                "DCSR has already been issued for key: {}",
                dcsr.display()
            ));
        }

        // Collect certs for the 4 trust anchors listed in the `root_labels`.
        // These are the 4 trust anchors trusted by the lpc55 verified boot.
        let mut certs: Vec<Certificate> = Vec::new();
        for label in spec.root_labels {
            let ca = cas.get(label.try_as_str()?).ok_or(anyhow!(
                "no Ca \"{}\" for DcsrSpec root labels",
                label
            ))?;
            certs.push(ca.cert()?);
        }
        let certs = certs;

        // Get public key from the cert of the Ca signing the Dcsr (self).
        let cert = self.cert()?;
        let signer_public_key = lpc55_sign::cert::public_key(&cert)?;

        // lpc55_sign ergonomics
        let debug_public_key = spec.dcsr.debug_public_key.clone();
        // Construct the to-be-signed debug credential
        let dc_tbs = lpc55_sign::debug_auth::debug_credential_tbs(
            certs,
            signer_public_key,
            spec.dcsr,
        )?;

        // Sign it using the private key stored in the HSM.
        let dc_sig = client.sign_rsa_pkcs1v15_sha256(self.spec.id, &dc_tbs)?;

        // Append the signature to the TBS debug credential to make a complete debug
        // credential
        let mut dc = Vec::new();
        dc.extend_from_slice(&dc_tbs);
        dc.extend_from_slice(&dc_sig.into_vec());

        // We do not fail this function if writing the signed DAC to the
        // DacStore fails because it has already been signed. Returning it to
        // the caller is paramount. We can fixup the DacStore in post.
        if let Err(e) = self.dacs.add(&debug_public_key, &dc) {
            error!(
                "DAC was signed successfully but we failed to write it to the \
                DacStore: {}",
                e
            );
        }

        Ok(dc)
    }
}

/// This utility function is used to create the directory structure required
/// for the CA.
fn bootstrap_ca_dir<P: AsRef<Path>>(
    spec: &KeySpec,
    root: P,
    pkcs11_lib: P,
) -> Result<()> {
    fs::create_dir_all(&root).with_context(|| {
        format!("Failed to create directory \"{}\"", root.as_ref().display())
    })?;

    // save current pwd so we can return to where we started
    let pwd = env::current_dir()?;
    env::set_current_dir(&root)?;

    // copy the key spec file to the ca state dir
    let spec_json = spec
        .to_json()
        .context("Failed to serialize KeySpec to json")?;
    fs::write(CA_KEY_SPEC, spec_json)?;

    // create directories expected by `openssl ca`
    for dir in ["crl", "newcerts", "csr", "private"] {
        fs::create_dir(dir)
            .with_context(|| format!("Failed to create directory: {dir}"))?;
        if dir == "private" {
            let perms = Permissions::from_mode(0o700);
            debug!("setting permissions on directory {} to {:#?}", dir, perms);
            fs::set_permissions(dir, perms)?;
        }
    }

    // touch 'index.txt' file
    let index = "index.txt";
    OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(index)?;

    // write initial serial number to 'serial' (echo 1000 > serial)
    let serial = "serial";
    let init_serial_hex = format!("{:020x}", spec.initial_serial_number);
    debug!(
        "setting initial serial number to \"{init_serial_hex}\" in file \"{serial}\""
    );
    fs::write(serial, init_serial_hex)?;

    // create & write out an openssl.cnf
    fs::write(
        "openssl.cnf",
        format!(
            openssl_cnf_fmt!(),
            key = spec.id,
            hash = spec.hash,
            pkcs11_path = pkcs11_lib.as_ref().display(),
        ),
    )?;

    Ok(env::set_current_dir(pwd)?)
}

/// If we've already executed an openssl command successfully it probably
/// signed something and created an artifact that *MUST* be returned to the
/// caller. We say *MUST* here because anything we sign must be accounted for
/// and if we run into an error cleaning up stuff and the error is propagated
/// to the caller an artifact may be lost. This would be bad so instead, this
/// function wraps up some operations that we try to do before returning some
/// data to the caller. Errors are logged as warnings but ignored otherwise.
fn teardown_warn_only<P: AsRef<Path>>(mut conn: Child, ret_path: P) {
    if let Err(e) = conn.kill() {
        warn!("Failed to kill the YubiHSM connector: {}", e);
    }
    if let Err(e) = env::set_current_dir(&ret_path) {
        warn!(
            "Failed to restore directory to {}: {}",
            ret_path.as_ref().display(),
            e
        );
    }
}

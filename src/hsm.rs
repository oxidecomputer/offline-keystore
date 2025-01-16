// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{Context, Result};
use log::{debug, error, info};
use pem_rfc7468::LineEnding;
use rand_core::{impls, CryptoRng, Error as RngError, RngCore};
use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    str::FromStr,
};
use thiserror::Error;
use yubihsm::{
    authentication::{self, Key, DEFAULT_AUTHENTICATION_KEY_ID},
    object::{Id, Label, Type},
    wrap::{self, Message},
    AuditOption, Capability, Client, Connector, Credentials, Domain,
    HttpConfig, UsbConfig,
};
use zeroize::Zeroizing;

use crate::{
    backup::BackupKey,
    config::{self, KeySpec, Transport, KEYSPEC_EXT},
};

const WRAP_ID: Id = 1;

const ALG: wrap::Algorithm = wrap::Algorithm::Aes256Ccm;
const CAPS: Capability = Capability::all();
const DELEGATED_CAPS: Capability = Capability::all();
const DOMAIN: Domain = Domain::all();
const ID: Id = 0x1;
const LABEL: &str = "backup";

const BACKUP_EXT: &str = ".backup.json";
const ATTEST_FILE_NAME: &str = "hsm.attest.cert.pem";

#[derive(Error, Debug)]
pub enum HsmError {
    #[error("path not a directory")]
    BadSpecDirectory,
    #[error("failed conversion from YubiHSM Domain")]
    BadDomain,
    #[error("failed to convert use input into a key share")]
    BadKeyShare,
    #[error("failed conversion from YubiHSM Label")]
    BadLabel,
    #[error("Invalid purpose for root CA key")]
    BadPurpose,
    #[error("Combined shares produced an invalid Scalar")]
    BadScalar,
    #[error("Failed to combined shares into wrap key.")]
    CombineKeyFailed { e: vsss_rs::Error },
    #[error("Failed to split wrap key into shares.")]
    SplitKeyFailed { e: vsss_rs::Error },
    #[error("your yubihms is broke")]
    Version,
    #[error("Not enough shares.")]
    NotEnoughShares,
}

/// Structure holding common data used by OKS when interacting with the HSM.
pub struct Hsm {
    pub client: Client,
    pub out_dir: PathBuf,
    pub state_dir: PathBuf,
    pub backup: bool,
}

impl Hsm {
    // 5 minute to support RSA4K key generation
    // NOTE: RSA key generation takes a lot of time on the YubiHSM. It's also
    // highly viariable: in practice we've seen RSA4K key generation take
    // anywhere from less than 1 minute to over 5 minutes.
    const TIMEOUT_MS: u64 = 300000;

    pub fn new(
        auth_id: Id,
        passwd: &str,
        out_dir: &Path,
        state_dir: &Path,
        backup: bool,
        transport: Transport,
    ) -> Result<Self> {
        let connector = match transport {
            Transport::Usb => {
                let config = UsbConfig {
                    serial: None,
                    timeout_ms: Self::TIMEOUT_MS,
                };
                Connector::usb(&config)
            }
            Transport::Http => {
                let config = HttpConfig::default();
                Connector::http(&config)
            }
        };

        let credentials =
            Credentials::from_password(auth_id, passwd.as_bytes());
        let client = Client::open(connector, credentials, true)?;

        Ok(Hsm {
            client,
            out_dir: out_dir.to_path_buf(),
            state_dir: state_dir.to_path_buf(),
            backup,
        })
    }

    /// Create a new wrap key, cut it up into shares, & a Feldman verifier,
    /// then put the key into the YubiHSM. The shares and the verifier are then
    /// returned to the caller. Generally they will then be distributed
    /// 'off-platform' somehow.
    pub fn import_backup_key(&mut self, key: BackupKey) -> Result<()> {
        info!(
            "Generating wrap / backup key from HSM PRNG with label: \"{}\"",
            LABEL.to_string()
        );

        info!("Storing wrap key in YubiHSM.");
        let id = self.client
            .put_wrap_key(
                ID,
                Label::from_bytes(LABEL.as_bytes())?,
                DOMAIN,
                CAPS,
                DELEGATED_CAPS,
                ALG,
                key.as_bytes(),
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
        Ok(())
    }

    // create a new auth key, remove the default auth key, then export the new
    // auth key under the wrap key with the provided id
    // NOTE: This function consume self because it deletes the auth credential
    // that was used to create the client object. To use the HSM after calling
    // this function you'll need to reauthenticate.
    pub fn replace_default_auth(
        self,
        password: &Zeroizing<String>,
    ) -> Result<()> {
        info!("Setting up new auth credential.");
        // Key implements Zeroize internally on drop
        let auth_key = Key::derive_from_password(password.as_bytes());

        debug!("putting new auth key from provided password");
        // create a new auth key
        self.client.put_authentication_key(
            AUTH_ID,
            AUTH_LABEL.into(),
            AUTH_DOMAINS,
            AUTH_CAPS,
            AUTH_DELEGATED,
            authentication::Algorithm::default(), // can't be used in const
            auth_key,
        )?;

        if self.backup {
            info!("Backing up new auth credential.");
            backup_object(
                &self.client,
                AUTH_ID,
                Type::AuthenticationKey,
                &self.out_dir,
            )?;
        }

        info!("Deleting default auth key.");
        self.client.delete_object(
            DEFAULT_AUTHENTICATION_KEY_ID,
            Type::AuthenticationKey,
        )?;

        Ok(())
    }

    pub fn add_auth(
        &self,
        auth_id: Id,
        password: &Zeroizing<String>,
    ) -> Result<()> {
        info!("Adding auth credential w/ Id: {}", auth_id);
        // Key implements Zeroize internally on drop
        let auth_key = Key::derive_from_password(password.as_bytes());

        // create a new auth key
        self.client
            .put_authentication_key(
                auth_id,
                AUTH_LABEL.into(),
                AUTH_DOMAINS,
                AUTH_CAPS,
                AUTH_DELEGATED,
                authentication::Algorithm::default(), // can't be used in const
                auth_key,
            )
            .with_context(|| format!("Putting auth key w/ Id: {}", auth_id))?;

        // backup the auth key
        if self.backup {
            backup_object(
                &self.client,
                auth_id,
                Type::AuthenticationKey,
                &self.out_dir,
            )
            .with_context(|| format!("Backup object w/ id: {}", auth_id))?;
        }

        Ok(())
    }

    pub fn delete_auth(&self, auth_id: Id) -> Result<()> {
        info!("Deleting default auth key w/ Id: {}.", auth_id);
        self.client
            .delete_object(auth_id, Type::AuthenticationKey)
            .with_context(|| format!("Delete auth key with Id: {}", auth_id))?;

        Ok(())
    }

    pub fn generate(&self, key_spec: &Path) -> Result<()> {
        debug!("canonical KeySpec path: {}", key_spec.display());

        let paths = if key_spec.is_file() {
            vec![key_spec.to_path_buf()]
        } else {
            config::files_with_ext(key_spec, KEYSPEC_EXT)?
        };

        if paths.is_empty() {
            return Err(anyhow::anyhow!(
                "no files with extension \"{}\" found in dir: {}",
                KEYSPEC_EXT,
                &key_spec.display()
            ));
        }

        for path in paths {
            let json = fs::read_to_string(&path)?;
            debug!("spec as json: {}", json);

            let spec = KeySpec::from_str(&json)?;
            debug!("KeySpec from {}: {:#?}", path.display(), spec);

            info!("Generating key for spec: {:?}", path);
            let id = self.generate_keyspec(&spec)?;
            if self.backup {
                backup_object(
                    &self.client,
                    id,
                    Type::AsymmetricKey,
                    &self.out_dir,
                )?;
            }
        }

        Ok(())
    }

    /// Generate an asymmetric key from the provided specification.
    fn generate_keyspec(&self, spec: &KeySpec) -> Result<Id> {
        let id = self.client.generate_asymmetric_key(
            spec.id,
            spec.label.clone(),
            spec.domain,
            spec.capabilities,
            spec.algorithm,
        )?;
        debug!("new {:#?} key w/ id: {}", spec.algorithm, id);

        // get yubihsm attestation
        info!("Getting attestation for key with label: {}", spec.label);
        let attest_cert =
            self.client.sign_attestation_certificate(spec.id, None)?;

        let attest_cert = pem_rfc7468::encode_string(
            "CERTIFICATE",
            LineEnding::default(),
            attest_cert.as_slice(),
        )?;

        let attest_path =
            self.out_dir.join(format!("{}.attest.cert.pem", spec.label));
        fs::write(attest_path, attest_cert)?;

        Ok(id)
    }

    /// Write the cert for default attesation key in hsm to the provided
    /// filepath or a default location under self.output
    pub fn dump_attest_cert<P: AsRef<Path>>(
        &self,
        out: Option<P>,
    ) -> Result<()> {
        info!("Collecting YubiHSM attestation cert.");
        debug!("extracting attestation certificate");
        let attest_cert = self.client.get_opaque(0)?;

        let attest_cert = pem_rfc7468::encode_string(
            "CERTIFICATE",
            LineEnding::default(),
            &attest_cert,
        )?;

        let attest_path = match out {
            Some(o) => {
                if o.as_ref().is_dir() {
                    o.as_ref().join(ATTEST_FILE_NAME)
                } else if o.as_ref().exists() {
                    // file exists ... overwrite it?
                    return Err(anyhow::anyhow!("File already exists."));
                } else {
                    o.as_ref().to_path_buf()
                }
            }
            None => self.out_dir.join(ATTEST_FILE_NAME),
        };

        debug!("writing attestation cert to: {}", attest_path.display());
        Ok(fs::write(&attest_path, attest_cert)?)
    }
}

impl RngCore for Hsm {
    fn next_u32(&mut self) -> u32 {
        impls::next_u32_via_fill(self)
    }
    fn next_u64(&mut self) -> u64 {
        impls::next_u64_via_fill(self)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.try_fill_bytes(dest)
            .expect("RNG failed to fill the provided buffer.")
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RngError> {
        // The yubihsm.rs client allocates memory for the bytes that we
        // request here. Then we copy them to the slice provided by the
        // caller. API impedence mismatch.
        let bytes = match self.client.get_pseudo_random(dest.len()) {
            Ok(b) => Ok(b),
            Err(e) => Err(RngError::new(e)),
        }?;
        dest.copy_from_slice(&bytes);
        Ok(())
    }
}

// This is required for Feldman::split_secret to use `Hms` as an RNG.
impl CryptoRng for Hsm {}

/// Provided a key ID and a object type this function will find the object
/// in the HSM and generate the appropriate KeySpec for it.
pub fn backup_object<P: AsRef<Path>>(
    client: &Client,
    id: Id,
    kind: Type,
    file: P,
) -> Result<()> {
    info!("Backing up object with id: {:#06x} and type: {}", id, kind);
    let message = client.export_wrapped(WRAP_ID, kind, id)?;
    debug!("Got Message: {:?}", &message);

    let json = serde_json::to_string(&message)?;
    debug!("JSON: {}", json);

    let path = if file.as_ref().is_dir() {
        // get info
        // append format!("{}.backup.json", info.label)
        let info = client.get_object_info(id, kind)?;
        file.as_ref().join(format!("{}.backup.json", info.label))
    } else if file.as_ref().exists() {
        // file exists ... overwrite it?
        return Err(anyhow::anyhow!("File already exists."));
    } else {
        file.as_ref().to_path_buf()
    };

    info!("Writing backup to: \"{}\"", path.display());
    Ok(fs::write(path, json)?)
}

pub fn delete(client: &Client, id: Id, kind: Type) -> Result<()> {
    info!("Deleting object with id: {} type: {}", &id, &kind);
    Ok(client.delete_object(id, kind)?)
}

pub fn restore<P: AsRef<Path>>(client: &Client, file: P) -> Result<()> {
    let file = file.as_ref();
    info!("Restoring from backups in: \"{}\"", &file.display());
    let paths = if file.is_file() {
        vec![file.to_path_buf()]
    } else {
        config::files_with_ext(file, BACKUP_EXT)?
    };

    if paths.is_empty() {
        return Err(anyhow::anyhow!("backup directory is empty"));
    }

    for path in paths {
        info!("Restoring wrapped backup from file: {}", path.display());
        let json = fs::read_to_string(path)?;
        debug!("backup json: {}", json);

        let message: Message = serde_json::from_str(&json)?;
        debug!("deserialized message: {:?}", &message);

        let handle = client.import_wrapped(WRAP_ID, message)?;
        info!(
            "Imported {} key with object id {}.",
            handle.object_type, handle.object_id
        );
    }

    Ok(())
}

pub fn dump_info(client: &Client) -> Result<()> {
    let info = client.device_info()?;
    println!("{:#?}", info);
    Ok(())
}

pub fn dump_sn(client: &Client) -> Result<()> {
    let info = client.device_info()?;
    println!("{}", info.serial_number);

    Ok(())
}

pub fn reset(client: &Client) -> Result<()> {
    let info = client.device_info()?;
    info!("resetting device with SN: {}", info.serial_number);

    if are_you_sure()? {
        client.reset_device()?;
        debug!("reset successful");
    } else {
        info!("reset aborted");
    }
    Ok(())
}

pub fn audit_lock(client: &Client) -> Result<()> {
    if are_you_sure()? {
        Ok(client.set_force_audit_option(AuditOption::Fix)?)
    } else {
        Err(anyhow::anyhow!("command aborted"))
    }
}

// consts for our authentication credential
const AUTH_DOMAINS: Domain = Domain::all();
const AUTH_CAPS: Capability = Capability::all();
const AUTH_DELEGATED: Capability = Capability::all();
const AUTH_ID: Id = 2;
const AUTH_LABEL: &str = "admin";

fn are_you_sure() -> Result<bool> {
    print!("Are you sure? (y/n):");
    io::stdout().flush()?;

    let mut buffer = String::new();
    io::stdin().read_line(&mut buffer)?;

    let buffer = buffer.trim().to_ascii_lowercase();
    debug!("got: \"{}\"", buffer);

    Ok(buffer == "y")
}

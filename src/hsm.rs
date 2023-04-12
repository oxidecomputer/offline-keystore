// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{Context, Result};
use hex::ToHex;
use log::{debug, error, info};
use p256::elliptic_curve::PrimeField;
use p256::{NonZeroScalar, ProjectivePoint, Scalar, SecretKey};
use pem_rfc7468::LineEnding;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use static_assertions as sa;
use std::fs::File;
use std::{
    env,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    str::FromStr,
};
use thiserror::Error;
use vsss_rs::{Feldman, Share};
use yubihsm::{
    authentication::{self, Key, DEFAULT_AUTHENTICATION_KEY_ID},
    object::{Id, Label, Type},
    wrap::{self, Message},
    Capability, Client, Domain,
};
use zeroize::Zeroize;

use crate::config::{self, KeySpec, KEYSPEC_EXT};

// string for environment variable used to pass in a NEW authentication
// password for the HSM
// NOTE: this variable is only relevant to the hsm::initialize function
pub const ENV_NEW_PASSWORD: &str = "OKS_NEW_PASSWORD";

const WRAP_ID: Id = 1;

const ALG: wrap::Algorithm = wrap::Algorithm::Aes256Ccm;
const CAPS: Capability = Capability::all();
const DELEGATED_CAPS: Capability = Capability::all();
const DOMAIN: Domain = Domain::all();
const ID: Id = 0x1;
const SEED_LEN: usize = 32;
const KEY_LEN: usize = 32;
const LABEL: &str = "backup";

const PASSWD_PROMPT: &str = "Enter new HSM password: ";
const PASSWD_PROMPT2: &str = "Enter password again to confirm: ";

const SHARES: usize = 5;
const THRESHOLD: usize = 3;
sa::const_assert!(THRESHOLD <= SHARES);

const BACKUP_EXT: &str = ".backup.json";

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
    #[error("Failed to combined shares into wrap key.")]
    CombineKeyFailed { e: vsss_rs::Error },
    #[error("Failed to split wrap key into shares.")]
    SplitKeyFailed { e: vsss_rs::Error },
    #[error("your yubihms is broke")]
    Version,
}

/// Structure holding common data used by OKS when interacting with the HSM.
pub struct Hsm {
    pub client: Client,
    pub out_dir: PathBuf,
    pub state_dir: PathBuf,
}

impl Hsm {
    /// Initialize a new YubiHSM 2 by creating:
    /// - a new wap key for backup
    /// - a new auth key derived from a user supplied password
    /// This new auth key is backed up / exported under wrap using the new wrap
    /// key. This backup is written to the provided directory path. Finally this
    /// function removes the default authentication credentials.
    pub fn initialize(&self, print_dev: &Path) -> Result<()> {
        info!(
            "Generating wrap / backup key from HSM PRNG with label: \"{}\"",
            LABEL.to_string()
        );
        // get 32 bytes from YubiHSM PRNG
        // TODO: zeroize
        let wrap_key = self.client.get_pseudo_random(KEY_LEN)?;
        let rng_seed = self.client.get_pseudo_random(SEED_LEN)?;
        let rng_seed: [u8; SEED_LEN] =
            rng_seed.try_into().map_err(|v: Vec<u8>| {
                anyhow::anyhow!(
                    "Expected vec with {} elements, got {}",
                    SEED_LEN,
                    v.len()
                )
            })?;
        let mut rng = ChaCha20Rng::from_seed(rng_seed);

        info!("Splitting wrap key into {} shares.", SHARES);
        let wrap_key = SecretKey::from_be_bytes(&wrap_key).unwrap();
        debug!("wrap key: {:?}", wrap_key.to_be_bytes());

        let nzs = wrap_key.to_nonzero_scalar();
        // we add a byte to the key length per instructions from the library:
        // https://docs.rs/vsss-rs/2.7.1/src/vsss_rs/lib.rs.html#34
        let (shares, verifier) = Feldman::<THRESHOLD, SHARES>::split_secret::<
            Scalar,
            ProjectivePoint,
            ChaCha20Rng,
            { KEY_LEN + 1 },
        >(*nzs.as_ref(), None, &mut rng)
        .map_err(|e| HsmError::SplitKeyFailed { e })?;

        let verifier_path = self.out_dir.join("verifier.json");
        debug!(
            "Serializing verifier as json to: {}",
            verifier_path.display()
        );

        let verifier = serde_json::to_string(&verifier)?;
        debug!("JSON: {}", verifier);

        fs::write(verifier_path, verifier)?;

        println!(
            "\nWARNING: The wrap / backup key has been created and stored in the\n\
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

            print_share(&mut print_file, i, SHARES, share.as_ref())?;
            println!(
                "When key custodian {} has collected their key share, press enter",
                share_num,
            );
            wait_for_line();
        }

        // put 32 random bytes into the YubiHSM as an Aes256Ccm wrap key
        info!("Storing wrap key in YubiHSM.");
        let id = self.client
            .put_wrap_key::<[u8; 32]>(
                ID,
                Label::from_bytes(LABEL.as_bytes())?,
                DOMAIN,
                CAPS,
                DELEGATED_CAPS,
                ALG,
                wrap_key.to_be_bytes().into(),
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

        self.personalize(WRAP_ID)?;

        Ok(())
    }

    // create a new auth key, remove the default auth key, then export the new
    // auth key under the wrap key with the provided id
    fn personalize(&self, wrap_id: Id) -> Result<()> {
        info!("Setting up new auth credential.");
        debug!(
            "personalizing with wrap key {} and out_dir {}",
            wrap_id,
            self.out_dir.display()
        );
        // get a new password from the user
        let mut password = match env::var(ENV_NEW_PASSWORD).ok() {
            Some(s) => {
                info!("got password from env");
                s
            }
            None => loop {
                let password =
                    rpassword::prompt_password(PASSWD_PROMPT).unwrap();
                let mut password2 =
                    rpassword::prompt_password(PASSWD_PROMPT2).unwrap();
                if password != password2 {
                    error!("the passwords entered do not match");
                } else {
                    password2.zeroize();
                    break password;
                }
            },
        };
        debug!("got the same password twice: {}", password);

        // not compatible with Zeroizing wrapper
        let auth_key = Key::derive_from_password(password.as_bytes());

        password.zeroize();

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

        info!("Backing up new auth credential.");
        backup(
            &self.client,
            AUTH_ID,
            Type::AuthenticationKey,
            &self.state_dir,
        )?;

        info!("Deleting default auth key.");
        self.client.delete_object(
            DEFAULT_AUTHENTICATION_KEY_ID,
            Type::AuthenticationKey,
        )?;

        info!("Collecting YubiHSM attestation cert.");
        dump_attest_cert(&self.client, &self.out_dir)?;

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
            backup(&self.client, id, Type::AsymmetricKey, &self.state_dir)?;
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

    /// This function prompts the user to enter M of the N backup shares. It
    /// uses these shares to reconstitute the wrap key. This wrap key can then
    /// be used to restore previously backed up / export wrapped keys.
    pub fn restore_wrap(&self) -> Result<()> {
        info!("Restoring HSM from backup");
        info!("Restoring backup / wrap key from shares");
        let mut shares: Vec<[u8; KEY_LEN + 1]> = Vec::new();

        for i in 1..=THRESHOLD {
            print!("Enter share[{}]: ", i);
            io::stdout().flush()?;
            shares.push(
                hex::decode(io::stdin().lines().next().unwrap().unwrap())?
                    .try_into()
                    .map_err(|_| HsmError::BadKeyShare)?,
            );
        }

        for (i, share) in shares.iter().enumerate() {
            debug!("share[{}]: {}", i, share.encode_hex::<String>());
        }

        let shares: Vec<Share<{ KEY_LEN + 1 }>> = shares
            .iter()
            .map(|s| Share::try_from(&s[..]).unwrap())
            .collect();
        let scalar = Feldman::<THRESHOLD, SHARES>::combine_shares::<
            Scalar,
            { KEY_LEN + 1 },
        >(&shares)
        .map_err(|e| HsmError::CombineKeyFailed { e })?;

        // from_repr deals in CtOptions, not regular Options?
        let nz_scalar = NonZeroScalar::from_repr(scalar.to_repr()).unwrap();
        let wrap_key = SecretKey::from(nz_scalar);

        debug!("restored wrap key: {:?}", wrap_key.to_be_bytes());

        // put restored wrap key the YubiHSM as an Aes256Ccm wrap key
        let id = self.client
            .put_wrap_key::<[u8; KEY_LEN]>(
                ID,
                Label::from_bytes(LABEL.as_bytes())?,
                DOMAIN,
                CAPS,
                DELEGATED_CAPS,
                ALG,
                wrap_key.to_be_bytes().into(),
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
}

/// Provided a key ID and a object type this function will find the object
/// in the HSM and generate the appropriate KeySpec for it.
pub fn backup<P: AsRef<Path>>(
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

// consts for our authentication credential
const AUTH_DOMAINS: Domain = Domain::all();
const AUTH_CAPS: Capability = Capability::all();
const AUTH_DELEGATED: Capability = Capability::all();
const AUTH_ID: Id = 2;
const AUTH_LABEL: &str = "admin";

fn dump_attest_cert<P: AsRef<Path>>(client: &Client, out: P) -> Result<()> {
    // dump cert for default attesation key in hsm
    debug!("extracting attestation certificate");
    let attest_cert = client.get_opaque(0)?;

    let attest_cert = pem_rfc7468::encode_string(
        "CERTIFICATE",
        LineEnding::default(),
        &attest_cert,
    )?;

    let attest_path = out.as_ref().join("hsm.attest.cert.pem");

    debug!("writing attestation cert to: {}", attest_path.display());
    Ok(fs::write(&attest_path, attest_cert)?)
}

/// This function is used when displaying key shares as a way for the user to
/// control progression through the key shares displayed in the terminal.
fn wait_for_line() {
    let _ = io::stdin().lines().next().unwrap().unwrap();
}

fn are_you_sure() -> Result<bool> {
    print!("Are you sure? (y/n):");
    io::stdout().flush()?;

    let mut buffer = String::new();
    io::stdin().read_line(&mut buffer)?;

    let buffer = buffer.trim().to_ascii_lowercase();
    debug!("got: \"{}\"", buffer);

    Ok(buffer == "y")
}

// Format a key share for printing with Epson ESC/P
#[rustfmt::skip]
pub fn print_share(
    print_file: &mut File,
    share_idx: usize,
    share_count: usize,
    share_data: &[u8],
) -> Result<()> {
    const ESC: u8 = 0x1b;
    const LF: u8 = 0x0a;
    const FF: u8 = 0x0c;
    const CR: u8 = 0x0d;

    // ESC/P specification recommends sending CR before LF and FF.  The latter commands
    // print the contents of the data buffer before their movement.  This can cause
    // double printing (bolding) in certain situations.  Sending CR clears the data buffer
    // without printing so sending it first avoids any double printing.

    print_file.write_all(&[
        ESC, '@' as u32 as u8, // Initialize Printer
        ESC, 'x' as u32 as u8, 1, // Select NLQ mode
        ESC, 'k' as u32 as u8, 1, // Select San Serif font
        ESC, '$' as u32 as u8, 112, 0, // Move to absolute horizontal position (0*256)+127
        ESC, 'E' as u32 as u8, // Select Bold
    ])?;
    print_file.write_all("Oxide Offline Keystore".as_bytes())?;
    print_file.write_all(&[
        CR, LF,
        ESC, 'F' as u32 as u8, // Deselect Bold
        ESC, '$' as u32 as u8, 112, 0, // Move to absolute horizontal position (0*256)+127
    ])?;
    print_file.write_all("Recovery Key Share ".as_bytes())?;
    print_file.write_all(&[
        ESC, '-' as u32 as u8, 1, // Select underscore
    ])?;
    print_file.write_all((share_idx + 1).to_string().as_bytes())?;
    print_file.write_all(&[
        ESC, '-' as u32 as u8, 0, // Deselect underscore
    ])?;
    print_file.write_all(" of ".as_bytes())?;
    print_file.write_all(&[
        ESC, '-' as u32 as u8, 1, // Select underscore
    ])?;
    print_file.write_all(share_count.to_string().as_bytes())?;
    print_file.write_all(&[
        ESC, '-' as u32 as u8, 0, // Deselect underscore
        CR, LF,
        CR, LF,
        ESC, 'D' as u32 as u8, 8, 20, 32, 44, 0, // Set horizontal tab stops
    ])?;

    for (i, chunk) in share_data
        .encode_hex::<String>()
        .as_bytes()
        .chunks(8)
        .enumerate()
    {
        if i % 4 == 0 {
            print_file.write_all(&[CR, LF])?;
        }
        print_file.write_all(&['\t' as u32 as u8])?;
        print_file.write_all(chunk)?;
    }

    print_file.write_all(&[CR, FF])?;
    Ok(())
}

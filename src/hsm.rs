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
use std::collections::HashSet;
use std::fs::File;
use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    str::FromStr,
};
use thiserror::Error;
use vsss_rs::{Feldman, FeldmanVerifier, Share};
use yubihsm::{
    authentication::{self, Key, DEFAULT_AUTHENTICATION_KEY_ID},
    object::{Id, Label, Type},
    wrap::{self, Message},
    Capability, Client, Connector, Credentials, Domain, HttpConfig, UsbConfig,
};
use zeroize::Zeroizing;

use crate::config::{self, KeySpec, Transport, KEYSPEC_EXT};

const WRAP_ID: Id = 1;

const ALG: wrap::Algorithm = wrap::Algorithm::Aes256Ccm;
const CAPS: Capability = Capability::all();
const DELEGATED_CAPS: Capability = Capability::all();
const DOMAIN: Domain = Domain::all();
const ID: Id = 0x1;
const SEED_LEN: usize = 32;
const KEY_LEN: usize = 32;
const SHARE_LEN: usize = KEY_LEN + 1;
const LABEL: &str = "backup";

const SHARES: usize = 5;
const THRESHOLD: usize = 3;
sa::const_assert!(THRESHOLD <= SHARES);

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
}

pub struct Alphabet {
    chars: Vec<char>,
}

impl Default for Alphabet {
    fn default() -> Self {
        Self::new()
    }
}

impl Alphabet {
    pub fn new() -> Self {
        let mut chars: HashSet<char> = HashSet::new();
        chars.extend('a'..='z');
        chars.extend('A'..='Z');
        chars.extend('0'..='9');

        // Remove visually similar characters
        chars = &chars - &HashSet::from(['l', 'I', '1']);
        chars = &chars - &HashSet::from(['B', '8']);
        chars = &chars - &HashSet::from(['O', '0']);

        // We generate random passwords from this alphabet by getting a byte
        // of random data from the HSM and using this value to pick
        // characters from the alphabet. Our alphabet cannot be larger than
        // the u8::MAX or it will ignore characters after the u8::MAXth.
        assert!(usize::from(u8::MAX) > chars.len());

        Alphabet {
            chars: chars.into_iter().collect(),
        }
    }

    pub fn get_char(&self, val: u8) -> Option<char> {
        let len = self.chars.len() as u8;
        // let rand = ;
        // Avoid biasing results by ensuring the random values we use
        // are a multiple of the length of the alphabet. If they aren't
        // we just get another.
        if val < u8::MAX - u8::MAX % len {
            Some(self.chars[(val % len) as usize])
        } else {
            None
        }
    }

    pub fn get_random_string(
        &self,
        get_rand_u8: impl Fn() -> Result<u8>,
        length: usize,
    ) -> Result<String> {
        let mut passwd = String::with_capacity(length + 1);

        for _ in 0..length {
            let char = loop {
                let rand = get_rand_u8()?;

                if let Some(char) = self.get_char(rand) {
                    break char;
                }
            };

            passwd.push(char);
        }

        Ok(passwd)
    }
}

/// Structure holding common data used by OKS when interacting with the HSM.
pub struct Hsm {
    pub client: Client,
    pub out_dir: PathBuf,
    pub state_dir: PathBuf,
    pub alphabet: Alphabet,
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
            alphabet: Alphabet::new(),
            backup,
        })
    }

    pub fn rand_string(&self, length: usize) -> Result<String> {
        self.alphabet.get_random_string(
            || Ok(self.client.get_pseudo_random(1)?[0]),
            length,
        )
    }

    /// create a new wrap key, cut it up into shares, print those shares to
    /// `print_dev` & put the wrap key in the HSM
    pub fn new_split_wrap(&self, print_dev: &Path) -> Result<()> {
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
        let wrap_key = SecretKey::from_be_bytes(&wrap_key)?;
        debug!("wrap key: {:?}", wrap_key.to_be_bytes());

        let nzs = wrap_key.to_nonzero_scalar();
        // we add a byte to the key length per instructions from the library:
        // https://docs.rs/vsss-rs/2.7.1/src/vsss_rs/lib.rs.html#34
        let (shares, verifier) = Feldman::<THRESHOLD, SHARES>::split_secret::<
            Scalar,
            ProjectivePoint,
            ChaCha20Rng,
            SHARE_LEN,
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

        wait_for_line()?;

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
            wait_for_line()?;

            print_share(&mut print_file, i, SHARES, share.as_ref())?;
            println!(
                "When key custodian {} has collected their key share, press enter",
                share_num,
            );
            wait_for_line()?;
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
                &self.state_dir,
            )?;
        }

        info!("Deleting default auth key.");
        self.client.delete_object(
            DEFAULT_AUTHENTICATION_KEY_ID,
            Type::AuthenticationKey,
        )?;

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
                    &self.state_dir,
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

    /// This function prompts the user to enter M of the N backup shares. It
    /// uses these shares to reconstitute the wrap key. This wrap key can then
    /// be used to restore previously backed up / export wrapped keys.
    pub fn restore_wrap(&self) -> Result<()> {
        info!("Restoring HSM from backup");
        info!("Restoring backup / wrap key from shares");
        // vector used to collect shares
        let mut shares: Vec<Share<SHARE_LEN>> = Vec::new();

        // deserialize verifier:
        // verifier was serialized to output/verifier.json in the provisioning ceremony
        // it must be included in and deserialized from the ceremony inputs
        let verifier = self.out_dir.join("verifier.json");
        let verifier = fs::read_to_string(verifier)?;
        let verifier: FeldmanVerifier<Scalar, ProjectivePoint, SHARE_LEN> =
            serde_json::from_str(&verifier)?;

        // get enough shares to recover backup key
        for _ in 1..=THRESHOLD {
            // attempt to get a single share until the custodian enters a
            // share that we can verify
            loop {
                // clear the screen, move cursor to (0,0), & prompt user
                print!("\x1B[2J\x1B[1;1H");
                print!("Enter share\n: ");
                io::stdout().flush()?;
                // get share from stdin
                let mut share = String::new();
                let share = match io::stdin().read_line(&mut share) {
                    Ok(count) => match count {
                        0 => {
                            // Ctrl^D / EOF
                            continue;
                        }
                        // 33 bytes -> 66 characters + 1 newline
                        67 => share,
                        _ => {
                            print!(
                                "\nexpected 67 characters, got {}.\n\n\
                                Press any key to try again ...",
                                share.len()
                            );
                            io::stdout().flush()?;

                            // wait for a keypress / 1 byte from stdin
                            let _ = io::stdin().read(&mut [0u8]).unwrap();
                            continue;
                        }
                    },
                    Err(e) => {
                        print!(
                            "Error from `Stdin::read_line`: {}\n\n\
                            Press any key to try again ...",
                            e
                        );
                        io::stdout().flush()?;

                        // wait for a keypress / 1 byte from stdin
                        let _ = io::stdin().read(&mut [0u8]).unwrap();
                        continue;
                    }
                };

                // drop all whitespace from line entered, interpret it as a
                // hex string that we decode
                let share: String =
                    share.chars().filter(|c| !c.is_whitespace()).collect();
                let share_vec = match hex::decode(share) {
                    Ok(share) => share,
                    Err(_) => {
                        println!(
                            "Failed to decode Share. The value entered \
                                 isn't a valid hex string: try again."
                        );
                        continue;
                    }
                };

                // construct a Share from the decoded hex string
                let share: Share<SHARE_LEN> =
                    match Share::try_from(&share_vec[..]) {
                        Ok(share) => share,
                        Err(_) => {
                            println!(
                                "Failed to convert share entered to Share \
                                type. The value entered is the wrong length \
                                ... try again."
                            );
                            continue;
                        }
                    };

                if verifier.verify(&share) {
                    // if we're going to switch from paper to CDs for key
                    // share persistence this is the most obvious place to
                    // put a keyshare on to a CD w/ lots of refactoring
                    shares.push(share);
                    print!(
                        "\nShare verified!\n\nPress any key to continue ..."
                    );
                    io::stdout().flush()?;

                    // wait for a keypress / 1 byte from stdin
                    let _ = io::stdin().read(&mut [0u8]).unwrap();
                    break;
                } else {
                    println!("Failed to verify share: try again");
                    continue;
                }
            }
        }

        print!("\x1B[2J\x1B[1;1H");

        let scalar = Feldman::<THRESHOLD, SHARES>::combine_shares::<
            Scalar,
            SHARE_LEN,
        >(&shares)
        .map_err(|e| HsmError::CombineKeyFailed { e })?;

        let nz_scalar = NonZeroScalar::from_repr(scalar.to_repr());
        let nz_scalar = if nz_scalar.is_some().into() {
            nz_scalar.unwrap()
        } else {
            return Err(HsmError::BadScalar.into());
        };
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

// consts for our authentication credential
const AUTH_DOMAINS: Domain = Domain::all();
const AUTH_CAPS: Capability = Capability::all();
const AUTH_DELEGATED: Capability = Capability::all();
const AUTH_ID: Id = 2;
const AUTH_LABEL: &str = "admin";

/// This function is used when displaying key shares as a way for the user to
/// control progression through the key shares displayed in the terminal.
fn wait_for_line() -> Result<()> {
    let _ = io::stdin().lines().next().unwrap()?;
    Ok(())
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

// Character pitch is assumed to be 10 CPI
const CHARACTERS_PER_INCH: usize = 10;

// Horizontal position location is measured in 1/60th of an inch
const UNITS_PER_INCH: usize = 60;

const UNITS_PER_CHARACTER: usize = UNITS_PER_INCH / CHARACTERS_PER_INCH;

// Page is 8.5" wide.  Using 17/2 to stay in integers.
const UNITS_PER_LINE: usize = 17 * UNITS_PER_INCH / 2;

const ESC: u8 = 0x1b;
const LF: u8 = 0x0a;
const FF: u8 = 0x0c;
const CR: u8 = 0x0d;

fn print_centered_line(print_file: &mut File, text: &[u8]) -> Result<()> {
    let text_width_units = text.len() * UNITS_PER_CHARACTER;

    let remaining_space = UNITS_PER_LINE - text_width_units;
    let half_remaining = remaining_space / 2;

    let n_h = (half_remaining / 256) as u8;
    let n_l = (half_remaining % 256) as u8;

    print_file.write_all(&[ESC, b'$', n_l, n_h])?;

    print_file.write_all(text)?;

    Ok(())
}

fn print_whitespace_notice(
    print_file: &mut File,
    data_type: &str,
) -> Result<()> {
    print_file.write_all(&[
        ESC, b'$', 0, 0, // Move to left edge
    ])?;

    let options = textwrap::Options::new(70)
        .initial_indent("     NOTE: ")
        .subsequent_indent("           ");
    let text = format!("Whitespace is a visual aid only and must be omitted when entering the {data_type}");

    for line in textwrap::wrap(&text, options) {
        print_file.write_all(&[CR, LF])?;
        print_file.write_all(line.as_bytes())?;
    }

    Ok(())
}

// Format a key share for printing with Epson ESC/P
#[rustfmt::skip]
pub fn print_share(
    print_file: &mut File,
    share_idx: usize,
    share_count: usize,
    share_data: &[u8],
) -> Result<()> {
    // ESC/P specification recommends sending CR before LF and FF.  The latter commands
    // print the contents of the data buffer before their movement.  This can cause
    // double printing (bolding) in certain situations.  Sending CR clears the data buffer
    // without printing so sending it first avoids any double printing.

    print_file.write_all(&[
        ESC, b'@', // Initialize Printer
        ESC, b'x', 1, // Select NLQ mode
        ESC, b'k', 1, // Select San Serif font
        ESC, b'E', // Select Bold
    ])?;
    print_centered_line(print_file, b"Oxide Offline Keystore")?;
    print_file.write_all(&[
        CR, LF,
        ESC, b'F', // Deselect Bold
    ])?;

    print_centered_line(print_file, format!("Recovery Key Share {} of {}",
            share_idx + 1, share_count).as_bytes())?;
    print_file.write_all(&[
        CR, LF,
        CR, LF,
        ESC, b'D', 8, 20, 32, 44, 0, // Set horizontal tab stops
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
        print_file.write_all(&[b'\t'])?;
        print_file.write_all(chunk)?;
    }

    print_file.write_all(&[CR, LF])?;

    print_whitespace_notice(print_file, "recovery key share")?;

    print_file.write_all(&[CR, FF])?;
    Ok(())
}

// Format a key share for printing with Epson ESC/P
#[rustfmt::skip]
pub fn print_password(
    print_dev: &Path,
    password: &Zeroizing<String>,
) -> Result<()> {
    println!(
        "\nWARNING: The HSM authentication password has been created and stored in\n\
        the YubiHSM. It will now be printed to {}.\n\
        Before this password is printed, the operator will be prompted to ensure\n\
        that the appropriate participant is in front of the printer to recieve\n\
        the printout.\n\n\
        Press enter to print the HSM password ...",
        print_dev.display(),
    );

    wait_for_line()?;

    let mut print_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(print_dev)?;

    // ESC/P specification recommends sending CR before LF and FF.  The latter commands
    // print the contents of the data buffer before their movement.  This can cause
    // double printing (bolding) in certain situations.  Sending CR clears the data buffer
    // without printing so sending it first avoids any double printing.

    print_file.write_all(&[
        ESC, b'@', // Initialize Printer
        ESC, b'x', 1, // Select NLQ mode
        ESC, b'k', 1, // Select San Serif font
        ESC, b'E', // Select Bold
    ])?;
    print_centered_line(&mut print_file, b"Oxide Offline Keystore")?;
    print_file.write_all(&[
        CR, LF,
        ESC, b'F', // Deselect Bold
    ])?;
    print_centered_line(&mut print_file, b"HSM Password")?;
    print_file.write_all(&[
        CR, LF,
        CR, LF,
        ESC, b'D', 8, 20, 32, 44, 0, // Set horizontal tab stops
        CR, LF,
    ])?;

    for (i, chunk) in password
        .as_bytes()
        .chunks(8)
        .enumerate()
    {
        if i % 4 == 0 {
            print_file.write_all(&[CR, LF])?;
        }
        print_file.write_all(&[b'\t'])?;
        print_file.write_all(chunk)?;
    }

    print_file.write_all(&[CR, LF])?;

    print_whitespace_notice(&mut print_file, "HSM password")?;

    print_file.write_all(&[CR, FF])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // secret split into the feldman verifier & shares below
    const SECRET: &str =
        "f259a45c17624b9317d8e292050c46a0f3d7387724b4cd26dd94f8bd3d1c0e1a";

    // verifier created and serialized to json by `new_split_wrap`
    const VERIFIER: &str = r#"
    {
        "generator": "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "commitments": [
            "02315e9e3cd76d0917ecd60378b75259bbdf2e35a31f46c05a497409d5d89c69dc",
            "0250e4e04d42e92bc15eecbe0789f5ac4831abe962df6b1eaed897e4634df702e3",
            "02dfc3c60074cb4896163e7e188f8ec93d3bd1e2fd2ed68854c9324e4a56e94cc7"
        ]
    }"#;

    // shares dumped to the printer by `new_split_wrap`
    const SHARE_ARRAY: [&str; SHARES] = [
        "01 b5b7dd6a 8ef8762f 0f266784 be191202 7b8a4b21 72fcb410 f28b2e1a e3669f9c",
        "02 042cfd2b 1ede9e78 d7827065 2d8c20ef 1cb43bf1 c722f2e3 a08ac387 b57b18f8",
        "03 ddb9039b c714c472 70ecfd33 53657366 51230043 6f56c6a8 cf074e89 ac1fc4d0",
        "04 425bf0bf 879ae818 db660def 2fa509f8 e221a80d 765153d1 a2d34dd7 d22d3321",
        "05 3215c494 6071096e 16eda298 c24ae4a6 497e28ab 2a41d768 036261f8 2063ae8d",
    ];

    fn secret_bytes() -> [u8; KEY_LEN] {
        let mut secret = [0u8; KEY_LEN];
        hex::decode_to_slice(SECRET, &mut secret).unwrap();

        secret
    }

    fn deserialize_share(share: &str) -> Result<Share<SHARE_LEN>> {
        // filter out whitespace to keep hex::decode happy
        let share: String =
            share.chars().filter(|c| !c.is_whitespace()).collect();
        let share = hex::decode(share)
            .context("failed to decode share from hex string")?;

        Ok(Share::try_from(&share[..])
            .context("Failed to construct Share from bytes.")?)
    }

    #[test]
    fn round_trip() -> Result<()> {
        use rand::rngs::ThreadRng;

        let secret = secret_bytes();
        let secret_key = SecretKey::from_be_bytes(&secret)?;
        let nzs = secret_key.to_nonzero_scalar();

        let mut rng = ThreadRng::default();
        let (shares, verifier) = Feldman::<THRESHOLD, SHARES>::split_secret::<
            Scalar,
            ProjectivePoint,
            ThreadRng,
            SHARE_LEN,
        >(*nzs.as_ref(), None, &mut rng)
        .map_err(|e| anyhow::anyhow!("failed to split secret: {}", e))?;

        for s in &shares {
            assert!(verifier.verify(s));
        }

        let scalar = Feldman::<THRESHOLD, SHARES>::combine_shares::<
            Scalar,
            SHARE_LEN,
        >(&shares)
        .map_err(|e| anyhow::anyhow!("failed to combine secret: {}", e))?;

        let nzs_dup = NonZeroScalar::from_repr(scalar.to_repr()).unwrap();
        let sk_dup = SecretKey::from(nzs_dup);
        let new_secret: [u8; KEY_LEN] = sk_dup.to_be_bytes().try_into()?;

        assert_eq!(new_secret, secret);

        Ok(())
    }

    // deserialize a verifier & use it to verify the shares in SHARE_ARRAY
    #[test]
    fn verify_shares() -> Result<()> {
        let verifier: FeldmanVerifier<Scalar, ProjectivePoint, SHARE_LEN> =
            serde_json::from_str(VERIFIER)
                .context("Failed to deserialize FeldmanVerifier from JSON.")?;

        for share in SHARE_ARRAY {
            let share = deserialize_share(share)?;
            assert!(verifier.verify(&share));
        }

        Ok(())
    }

    #[test]
    fn verify_zero_share() -> Result<()> {
        let verifier: FeldmanVerifier<Scalar, ProjectivePoint, SHARE_LEN> =
            serde_json::from_str(VERIFIER)
                .context("Failed to deserialize FeldmanVerifier from JSON.")?;

        let share: Share<SHARE_LEN> =
            Share::try_from([0u8; SHARE_LEN].as_ref())
                .context("Failed to create Share from static array.")?;

        assert!(!verifier.verify(&share));

        Ok(())
    }

    // TODO: I had expected that changing a single bit in a share would case
    // the verifier to fail but that seems to be very wrong.
    #[test]
    fn verify_share_with_changed_byte() -> Result<()> {
        let verifier: FeldmanVerifier<Scalar, ProjectivePoint, SHARE_LEN> =
            serde_json::from_str(VERIFIER)
                .context("Failed to deserialize FeldmanVerifier from JSON.")?;

        let mut share = deserialize_share(SHARE_ARRAY[0])?;
        println!("share: {}", share.0[0]);
        share.0[1] = 0xff;
        share.0[2] = 0xff;
        share.0[3] = 0xff;
        // If we don't change the next byte this test will start failing.
        // I had (wrongly?) expected that the share would fail to verify w/
        // a single changed byte
        share.0[4] = 0xff;

        assert!(!verifier.verify(&share));

        Ok(())
    }

    #[test]
    fn recover_secret() -> Result<()> {
        let mut shares: Vec<Share<SHARE_LEN>> = Vec::new();
        for share in SHARE_ARRAY {
            shares.push(deserialize_share(share)?);
        }

        let scalar = Feldman::<THRESHOLD, SHARES>::combine_shares::<
            Scalar,
            SHARE_LEN,
        >(&shares)
        .map_err(|e| anyhow::anyhow!("failed to combine secret: {}", e))?;

        let nzs_dup = NonZeroScalar::from_repr(scalar.to_repr()).unwrap();
        let sk_dup = SecretKey::from(nzs_dup);
        let secret: [u8; KEY_LEN] = sk_dup.to_be_bytes().try_into()?;

        assert_eq!(secret, secret_bytes());

        Ok(())
    }
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{Context, Result};
use log::{debug, error, info};
use p256::elliptic_curve::PrimeField;
use p256::{NonZeroScalar, ProjectivePoint, Scalar, SecretKey};
use pem_rfc7468::LineEnding;
use rand_core::{impls, CryptoRng, Error as RngError, RngCore};
use static_assertions as sa;
use std::collections::HashSet;
use std::{
    fs,
    io::{self, Write},
    ops::Deref,
    path::{Path, PathBuf},
    str::FromStr,
};
use thiserror::Error;
use vsss_rs::{Feldman, FeldmanVerifier};
use yubihsm::{
    authentication::{self, Key, DEFAULT_AUTHENTICATION_KEY_ID},
    object::{Id, Label, Type},
    wrap::{self, Message},
    AuditOption, Capability, Client, Connector, Credentials, Domain,
    HttpConfig, UsbConfig,
};
use zeroize::Zeroizing;

use crate::config::{self, KeySpec, Transport, KEYSPEC_EXT};

const WRAP_ID: Id = 1;

const ALG: wrap::Algorithm = wrap::Algorithm::Aes256Ccm;
const CAPS: Capability = Capability::all();
const DELEGATED_CAPS: Capability = Capability::all();
const DOMAIN: Domain = Domain::all();
const ID: Id = 0x1;
const KEY_LEN: usize = 32;
const SHARE_LEN: usize = KEY_LEN + 1;
const LABEL: &str = "backup";

pub const LIMIT: usize = 5;
pub const THRESHOLD: usize = 3;
sa::const_assert!(THRESHOLD <= LIMIT);

const BACKUP_EXT: &str = ".backup.json";
const ATTEST_FILE_NAME: &str = "hsm.attest.cert.pem";

pub type Share = vsss_rs::Share<SHARE_LEN>;
pub type SharesMax = [Share; LIMIT];
pub type Verifier = FeldmanVerifier<Scalar, ProjectivePoint, THRESHOLD>;

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

    /// Create a new wrap key, cut it up into shares, & a Feldman verifier,
    /// then put the key into the YubiHSM. The shares and the verifier are then
    /// returned to the caller. Generally they will then be distributed
    /// 'off-platform' somehow.
    pub fn new_split_wrap(
        &mut self,
    ) -> Result<(Zeroizing<SharesMax>, Verifier)> {
        info!(
            "Generating wrap / backup key from HSM PRNG with label: \"{}\"",
            LABEL.to_string()
        );
        // get 32 bytes from YubiHSM PRNG
        // TODO: zeroize
        let mut wrap_key = [0u8; KEY_LEN];
        self.try_fill_bytes(&mut wrap_key)?;
        let wrap_key = wrap_key;

        info!("Splitting wrap key into {} shares.", LIMIT);
        let wrap_key = SecretKey::from_be_bytes(&wrap_key)?;
        debug!("wrap key: {:?}", wrap_key.to_be_bytes());

        let nzs = wrap_key.to_nonzero_scalar();
        // we add a byte to the key length per instructions from the library:
        // https://docs.rs/vsss-rs/2.7.1/src/vsss_rs/lib.rs.html#34
        let (shares, verifier) = Feldman::<THRESHOLD, LIMIT>::split_secret::<
            Scalar,
            ProjectivePoint,
            Self,
            SHARE_LEN,
        >(*nzs.as_ref(), None, &mut *self)
        .map_err(|e| HsmError::SplitKeyFailed { e })?;

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

        Ok((Zeroizing::new(shares), verifier))
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
    /// This function prompts the user to enter M of the N backup shares. It
    /// uses these shares to reconstitute the wrap key. This wrap key can then
    /// be used to restore previously backed up / export wrapped keys.
    pub fn restore_wrap(&self, shares: Zeroizing<Vec<Share>>) -> Result<()> {
        info!("Restoring HSM from backup");

        if shares.len() < THRESHOLD {
            return Err(HsmError::NotEnoughShares.into());
        }

        let scalar = Feldman::<THRESHOLD, LIMIT>::combine_shares::<
            Scalar,
            SHARE_LEN,
        >(shares.deref())
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
            "022f65c477affe7de97a51b8e562e763030218a8f0a8ecd7c349a50df7ded44985",
            "03365076080ebeeab74e2421fa0f4e4c5796ad3cbd157cc0405b100a45ae89f22f",
            "02bbd29359d702ff89ab2cbdb9e6ae102dfb1c4108aeab0701a469f28f0ad1e813"
        ]
    }"#;

    // shares dumped to the printer by `new_split_wrap`
    const SHARE_ARRAY: [&str; LIMIT] = [
        "01a69b62eb1a7c9deb5435ca73bf6f5e280279ba9cbdcd873d4decb665fb8aaf34",
        "020495513aa59e274196125218ff57b2f01f6bf97d817d24a1a00c5fbf29af08a8",
        "030c476f49b8c6e796dd6e7981c4c544f90794efc716db43d8c7adbf8bc3ec3fc7",
        "04bdb1bd1853f6deeb2a4a40ae0fb81442baf49d797de7e4e2c4d0d5cbca425491",
        "0518d43aa8772e0d3c7ca5a79de03020cdbfbd0d396873cab5b0020cf943eafc64",
    ];

    fn secret_bytes() -> [u8; KEY_LEN] {
        let mut secret = [0u8; KEY_LEN];
        hex::decode_to_slice(SECRET, &mut secret).unwrap();

        secret
    }

    fn deserialize_share(share: &str) -> Result<Share> {
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
        let (shares, verifier) = Feldman::<THRESHOLD, LIMIT>::split_secret::<
            Scalar,
            ProjectivePoint,
            ThreadRng,
            SHARE_LEN,
        >(*nzs.as_ref(), None, &mut rng)
        .map_err(|e| anyhow::anyhow!("failed to split secret: {}", e))?;

        for s in &shares {
            assert!(verifier.verify(s));
        }

        let scalar = Feldman::<THRESHOLD, LIMIT>::combine_shares::<
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
        let verifier: Verifier = serde_json::from_str(VERIFIER)
            .context("Failed to deserialize Verifier from JSON.")?;

        for share in SHARE_ARRAY {
            let share = deserialize_share(share)?;
            assert!(verifier.verify(&share));
        }

        Ok(())
    }

    #[test]
    fn verify_zero_share() -> Result<()> {
        let verifier: Verifier = serde_json::from_str(VERIFIER)
            .context("Failed to deserialize FeldmanVerifier from JSON.")?;

        let share = Share::try_from([0u8; SHARE_LEN].as_ref())
            .context("Failed to create Share from static array.")?;

        assert!(!verifier.verify(&share));

        Ok(())
    }

    // TODO: I had expected that changing a single bit in a share would case
    // the verifier to fail but that seems to be very wrong.
    #[test]
    fn verify_share_with_changed_byte() -> Result<()> {
        let verifier: Verifier = serde_json::from_str(VERIFIER)
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
        let mut shares: Vec<Share> = Vec::new();
        for share in SHARE_ARRAY {
            shares.push(deserialize_share(share)?);
        }

        let scalar = Feldman::<THRESHOLD, LIMIT>::combine_shares::<
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

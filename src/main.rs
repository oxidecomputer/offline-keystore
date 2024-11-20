// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use env_logger::Builder;
use log::{debug, error, info, LevelFilter};
use std::{
    collections::HashMap,
    env, fs,
    ops::{Deref, DerefMut},
    path::{Path, PathBuf},
    str::FromStr,
};
use yubihsm::object::{Id, Type};
use zeroize::Zeroizing;

use oks::{
    ca::{Ca, CertOrCsr},
    config::{
        self, CsrSpec, DcsrSpec, KeySpec, Transport, CSRSPEC_EXT, DCSRSPEC_EXT,
        ENV_NEW_PASSWORD, ENV_PASSWORD, KEYSPEC_EXT,
    },
    hsm::{Hsm, Share, Verifier, LIMIT, THRESHOLD},
    secret_reader::{StdioPasswordReader, StdioShareReader},
    secret_writer::{PrinterSecretWriter, DEFAULT_PRINT_DEV},
    util,
};

const PASSWD_PROMPT: &str = "Enter YubiHSM Password: ";
const PASSWD_NEW: &str = "Enter new password: ";
const PASSWD_NEW_2: &str = "Enter password again to confirm: ";

const GEN_PASSWD_LENGTH: usize = 16;
const VERIFIER_FILE: &str = "verifier.json";

// when we write out signed certs to the file system this suffix is appended
const CERT_SUFFIX: &str = "cert.pem";

// when we write out signed debug credentials to the file system this suffix
// is appended
const DCSR_SUFFIX: &str = "dc.bin";

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
/// Create and restore split yubihsm wrap keys
struct Args {
    /// Increase verbosity
    #[clap(long, env)]
    verbose: bool,

    /// Directory where we put certs and attestations
    #[clap(long, env, default_value = "output")]
    output: PathBuf,

    /// Directory where we put KeySpec, CA state and backups
    #[clap(long, env, default_value = "ca-state")]
    state: PathBuf,

    /// 'usb' or 'http'
    #[clap(long, env, default_value = "usb")]
    transport: Transport,

    /// subcommands
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug, PartialEq)]
enum Command {
    Ca {
        #[command(subcommand)]
        command: CaCommand,
    },
    Hsm {
        /// ID of authentication credential
        #[clap(long, env)]
        auth_id: Option<Id>,

        /// Skip creation of a wrap key when initializing the HSM.
        #[clap(long, env)]
        no_backup: bool,

        #[command(subcommand)]
        command: HsmCommand,
    },
    /// Execute the OKS provisioning ceremony in a single command. This
    /// is equivalent to executing `hsm initialize`, `hsm generate`,
    /// `ca initialize`, and `ca sign`.
    Ceremony {
        #[clap(long, env, default_value = "input")]
        csr_spec: PathBuf,

        #[clap(long, env, default_value = "input")]
        key_spec: PathBuf,

        /// Path to the YubiHSM PKCS#11 module
        #[clap(
            long,
            env = "OKS_PKCS11_PATH",
            default_value = "/usr/lib/pkcs11/yubihsm_pkcs11.so"
        )]
        pkcs11_path: PathBuf,

        #[clap(long, env, default_value = DEFAULT_PRINT_DEV)]
        print_dev: PathBuf,

        #[clap(long, env)]
        /// Challenge the caller for a new password, don't generate a
        /// random one for them.
        passwd_challenge: bool,
    },
}

#[derive(Subcommand, Debug, PartialEq)]
/// Commands for operating on the CAs associated with keys in the HSM.
enum CaCommand {
    /// Initialize an OpenSSL CA for the given key.
    Initialize {
        /// Spec file describing the CA signing key
        #[clap(long, env, default_value = "input")]
        key_spec: PathBuf,

        /// Path to the YubiHSM PKCS#11 module
        #[clap(
            long,
            env = "OKS_PKCS11_PATH",
            default_value = "/usr/lib/pkcs11/yubihsm_pkcs11.so"
        )]
        pkcs11_path: PathBuf,
    },

    /// Use the CA associated with the provided key spec to sign the
    /// provided CSR.
    Sign {
        #[clap(long, env, default_value = "input")]
        csr_spec: PathBuf,
    },
}

#[derive(Subcommand, Clone, Debug, PartialEq)]
#[clap(verbatim_doc_comment)]
/// Commands for interacting with the YubiHSM2 during key ceremonies.
/// Behavior of this command is influenced by the following environment
/// variables:
/// - OKS_PASSWORD - if set this command will use the value from this
///   variable for authention with the HSM
/// - OKS_NEW_PASSWORD - if set this command will use the value from this
///   variable as the password for a newly created admin auth credential
enum HsmCommand {
    /// Generate keys in YubiHSM from specification.
    Generate {
        #[clap(long, env, default_value = "input")]
        key_spec: PathBuf,
    },

    /// Initialize the YubiHSM for use in the OKS.
    Initialize {
        #[clap(long, env, default_value = "/dev/usb/lp0")]
        print_dev: PathBuf,

        #[clap(long, env)]
        /// Challenge the caller for a new password, don't generate a
        /// random one for them.
        passwd_challenge: bool,
    },

    /// Restore a previously split aes256-ccm-wrap key
    Restore {
        #[clap(long, env, default_value = "input")]
        backups: PathBuf,

        #[clap(long, env, default_value = "input/verifier.json")]
        verifier: PathBuf,
    },

    /// Get serial number from YubiHSM and dump to console.
    SerialNumber,
}

fn make_dir(path: &Path) -> Result<()> {
    if !path.try_exists()? {
        // output directory doesn't exist, create it
        info!(
            "required directory does not exist, creating: \"{}\"",
            path.display()
        );
        Ok(fs::create_dir_all(path)?)
    } else if !path.is_dir() {
        Err(anyhow!(
            "directory provided is not a directory: \"{}\"",
            path.display()
        ))
    } else {
        Ok(())
    }
}

/// Get auth_id, pick reasonable defaults if not set.
fn get_auth_id(auth_id: Option<Id>, command: &HsmCommand) -> Id {
    match auth_id {
        // if auth_id is set by the caller we use that value
        Some(a) => a,
        None => match command {
            // for these HSM commands we assume YubiHSM2 is in its
            // default state and we use the default auth credentials:
            // auth_id 1
            HsmCommand::Initialize {
                print_dev: _,
                passwd_challenge: _,
            }
            | HsmCommand::Restore { .. }
            | HsmCommand::SerialNumber => 1,
            // otherwise we assume the auth key that we create is
            // present: auth_id 2
            _ => 2,
        },
    }
}

/// Get password either from environment, the YubiHSM2 default, or challenge
/// the user with a password prompt.
fn get_passwd(
    auth_id: Option<Id>,
    command: &HsmCommand,
) -> Result<Zeroizing<String>> {
    let passwd = match env::var(ENV_PASSWORD).ok() {
        Some(s) => Zeroizing::new(s),
        None => {
            let passwd_reader = StdioPasswordReader::default();
            if auth_id.is_some() {
                // if auth_id was set by the caller but not the password we
                // prompt for the password
                passwd_reader.read(PASSWD_PROMPT)?
            } else {
                match command {
                    // if password isn't set, auth_id isn't set, and
                    // the command is one of these, we assume the
                    // YubiHSM2 is in its default state so we use the
                    // default password
                    HsmCommand::Initialize {
                        print_dev: _,
                        passwd_challenge: _,
                    }
                    | HsmCommand::Restore { .. }
                    | HsmCommand::SerialNumber => {
                        Zeroizing::new("password".to_string())
                    }
                    // otherwise prompt the user for the password
                    _ => passwd_reader.read(PASSWD_PROMPT)?,
                }
            }
        }
    };

    Ok(passwd)
}

/// get a new password from the environment or by issuing a challenge the user
fn get_new_passwd(hsm: Option<&Hsm>) -> Result<Zeroizing<String>> {
    let passwd = match env::var(ENV_NEW_PASSWORD).ok() {
        // prefer new password from env above all else
        Some(s) => {
            info!("got password from env");
            Zeroizing::new(s)
        }
        None => match hsm {
            // use the HSM otherwise if available
            Some(hsm) => {
                info!("Generating random password");
                Zeroizing::new(hsm.rand_string(GEN_PASSWD_LENGTH)?)
            }
            // last option: challenge the caller
            None => {
                let passwd_reader = StdioPasswordReader::default();
                loop {
                    let password = passwd_reader.read(PASSWD_NEW)?;
                    let password2 = passwd_reader.read(PASSWD_NEW_2)?;
                    if password != password2 {
                        error!("the passwords entered do not match");
                    } else {
                        debug!("got the same password twice");
                        break password;
                    }
                }
            }
        },
    };

    Ok(passwd)
}

/// Perform all operations that make up the ceremony for provisioning an
/// offline keystore.
fn do_ceremony<P: AsRef<Path>>(
    csr_spec: P,
    key_spec: P,
    pkcs11_path: P,
    print_dev: P,
    challenge: bool,
    args: &Args,
) -> Result<()> {
    let passwd_new = {
        // assume YubiHSM is in default state: use default auth credentials
        let passwd = "password".to_string();
        let mut hsm = Hsm::new(
            1,
            &passwd,
            &args.output,
            &args.state,
            true,
            args.transport,
        )?;

        let (shares, verifier) = hsm.new_split_wrap()?;
        let verifier = serde_json::to_string(&verifier)?;
        debug!("JSON: {}", verifier);
        let verifier_path = args.output.join(VERIFIER_FILE);
        debug!(
            "Serializing verifier as json to: {}",
            verifier_path.display()
        );

        fs::write(verifier_path, verifier)?;

        println!(
            "\nWARNING: The wrap / backup key has been created and stored in the\n\
            YubiHSM. It will now be split into {} key shares and each share\n\
            will be individually written to {}. Before each keyshare is\n\
            printed, the operator will be prompted to ensure the appropriate key\n\
            custodian is present in front of the printer.\n\n\
            Press enter to begin the key share recording process ...",
            LIMIT,
            print_dev.as_ref().display(),
        );

        let secret_writer = PrinterSecretWriter::new(Some(print_dev));
        for (i, share) in shares.as_ref().iter().enumerate() {
            let share_num = i + 1;
            println!(
                "When key custodian {num} is ready, press enter to print share \
                {num}",
                num = share_num,
            );
            util::wait_for_line()?;

            // we're iterating over &Share so we've gotta clone it to wrap it
            // in a `Zeroize` like `share` expects
            secret_writer.share(i, LIMIT, &Zeroizing::new(*share))?;
            println!(
                "When key custodian {} has collected their key share, press enter",
                share_num,
            );
            util::wait_for_line()?;
        }
        info!("Collecting YubiHSM attestation cert.");
        hsm.dump_attest_cert::<String>(None)?;

        let passwd = if challenge {
            get_new_passwd(None)?
        } else {
            get_new_passwd(Some(&hsm))?
        };

        secret_writer.password(&passwd)?;
        hsm.replace_default_auth(&passwd)?;
        passwd
    };
    {
        // use new password to auth
        let hsm = Hsm::new(
            2,
            &passwd_new,
            &args.output,
            &args.state,
            true,
            args.transport,
        )?;
        hsm.generate(key_spec.as_ref())?;
    }

    // set env var for oks::ca module to pickup for PKCS11 auth
    env::set_var(ENV_PASSWORD, &passwd_new);
    // for each key_spec in `key_spec` initialize Ca
    let cas = initialize_all_ca(
        key_spec.as_ref(),
        pkcs11_path.as_ref(),
        &args.state,
        &args.output,
    )?;
    sign_all(
        &cas,
        csr_spec.as_ref(),
        &args.state,
        &args.output,
        args.transport,
    )
}

pub fn initialize_all_ca<P: AsRef<Path>>(
    key_spec: P,
    pkcs11_path: P,
    ca_state: P,
    out: P,
) -> Result<HashMap<String, Ca>> {
    let key_spec = fs::canonicalize(key_spec)?;
    debug!("canonical KeySpec path: {}", key_spec.display());

    let paths = if key_spec.is_file() {
        vec![key_spec.clone()]
    } else {
        config::files_with_ext(&key_spec, KEYSPEC_EXT)?
    };

    if paths.is_empty() {
        return Err(anyhow!(
            "no files with extension \"{}\" found in dir: {}",
            KEYSPEC_EXT,
            &key_spec.display()
        ));
    }

    // all state directories for the CAs are created under this directory
    fs::create_dir_all(ca_state.as_ref()).with_context(|| {
        format!(
            "Failed to create directory to hold CA state: {}",
            ca_state.as_ref().display()
        )
    })?;

    let mut map = HashMap::new();
    for key_spec in paths {
        let spec = fs::canonicalize(&key_spec)?;
        debug!("canonical KeySpec path: {}", spec.display());

        if !spec.is_file() {
            return Err(anyhow!("path to KeySpec isn't a file"));
        }

        let spec_json = fs::read_to_string(spec)?;
        let spec = KeySpec::from_str(&spec_json)?;

        let label = spec.label.to_string();
        let ca_dir = fs::canonicalize(ca_state.as_ref())?.join(&label);

        // Initialize the a CA with the key defined by the KeySpec
        let cert_or_csr =
            Ca::initialize(&spec, ca_dir.as_path(), pkcs11_path.as_ref())
                .with_context(|| {
                    format!(
                        "Failed to initialize Ca from keyspec: {}",
                        key_spec.display()
                    )
                })?;

        let (path, pem) = match cert_or_csr {
            CertOrCsr::Cert(p) => {
                (out.as_ref().join(format!("{}.cert.pem", spec.label)), p)
            }
            CertOrCsr::Csr(p) => {
                (out.as_ref().join(format!("{}.csr.pem", spec.label)), p)
            }
        };
        fs::write(&path, pem).with_context(|| {
            format!("Failed to write PEM to path: {}", path.display())
        })?;

        //
        let ca = Ca::load(ca_dir.as_path())?;
        if map.insert(ca.name(), ca).is_some() {
            return Err(anyhow!("duplicate key label"));
        }
    }

    Ok(map)
}

pub fn load_all_ca<P: AsRef<Path>>(ca_state: P) -> Result<HashMap<String, Ca>> {
    // find all directories under `ca_state`
    // for each directory in `ca_state`, Ca::load(directory)
    // insert into hash map
    let dirs: Vec<PathBuf> = fs::read_dir(ca_state.as_ref())?
        .filter(|x| x.is_ok()) // filter out error variant to make unwrap safe
        .map(|r| r.unwrap().path()) // get paths
        .filter(|x| x.is_dir()) // filter out every path that isn't a directory
        .collect();
    let mut cas: HashMap<String, Ca> = HashMap::new();
    for dir in dirs {
        let ca = Ca::load(dir)?;
        if cas.insert(ca.name(), ca).is_some() {
            return Err(anyhow!("found CA with duplicate key label"));
        }
    }

    Ok(cas)
}

// Get the CsrSpec from the provided file and use the HashMap of `Ca`s to find
// the `Ca` that should sign it. Returns a PEM encoded x509 certificate as a
// Vec<u8>.
fn sign_csrspec<P: AsRef<Path>>(
    spec: P,
    cas: &HashMap<String, Ca>,
) -> Result<Vec<u8>> {
    let json = fs::read_to_string(&spec).with_context(|| {
        format!(
            "Failed to read CsrSpec json from {}",
            spec.as_ref().display()
        )
    })?;
    let csr_spec = CsrSpec::from_str(&json)?;

    let ca_name = csr_spec.label.to_string();
    let signer = cas
        .get(&ca_name)
        .ok_or(anyhow!("no CA \"{}\" for CsrSpec", ca_name))?;

    info!("Signing CSR from CsrSpec: {}", spec.as_ref().display());
    signer.sign_csrspec(&csr_spec)
}

// Get the DcsrSpec from the provided file, generate a debug credential from
// it, then sign it with the appropriate `Ca`.
fn sign_dcsrspec<P: AsRef<Path>>(
    spec: P,
    cas: &HashMap<String, Ca>,
    hsm: &mut Hsm,
) -> Result<Vec<u8>> {
    let json = std::fs::read_to_string(&spec).with_context(|| {
        format!(
            "Failed to read DcsrSpec json from {}",
            spec.as_ref().display()
        )
    })?;
    let dcsr_spec: DcsrSpec = serde_json::from_str(&json)
        .context("Failed to deserialize DcsrSpec from json")?;
    let ca_name = dcsr_spec.label.to_string();
    let signer = cas
        .get(&ca_name)
        .ok_or(anyhow!("no Ca \"{}\" for DcsrSpec", ca_name))?;

    info!("Signing DCSR from DcsrSpec: {}", spec.as_ref().display());
    let dc = signer.sign_dcsrspec(dcsr_spec, cas, &hsm.client)?;
    hsm.client.close_session()?;

    Ok(dc)
}

// Process all relevant spec files (CsrSpec & DcsrSpec) from the provided
// path. From these spec files we determine which Ca should sign them. The
// resulting certs / credentials are written to `out`.
pub fn sign_all<P: AsRef<Path>>(
    cas: &HashMap<String, Ca>,
    spec: P,
    state: P,
    out: P,
    transport: Transport,
) -> Result<()> {
    let spec = fs::canonicalize(spec)?;
    debug!("canonical spec path: {}", &spec.display());

    let paths = if spec.is_file() {
        vec![spec.clone()]
    } else {
        config::files_with_ext(&spec, CSRSPEC_EXT)?
            .into_iter()
            .chain(config::files_with_ext(&spec, DCSRSPEC_EXT)?)
            .collect::<Vec<PathBuf>>()
    };

    if paths.is_empty() {
        return Err(anyhow!(
            "no files with extensions \"{}\" or \"{}\" found in dir: {}",
            CSRSPEC_EXT,
            DCSRSPEC_EXT,
            &spec.display()
        ));
    }

    for path in paths {
        let filename = path.file_name().unwrap().to_string_lossy();

        let prefix = {
            // Write the cert to the output directory. We give this output
            // file the same prefix as the spec file.
            let filename = match path
                .file_name()
                .ok_or(anyhow!("Invalid path to DcsrSpec file"))?
                .to_os_string()
                .into_string()
            {
                Ok(s) => s,
                Err(s) => {
                    return Err(anyhow!(
                        "Invalid path to CsrSpec file: \"{:?}\"",
                        s
                    ))
                }
            };
            match filename.find('.') {
                Some(i) => filename[..i].to_string(),
                None => filename,
            }
        };

        let (suffix, data) = if filename.ends_with(CSRSPEC_EXT) {
            (CERT_SUFFIX, sign_csrspec(path, cas)?)
        } else if filename.ends_with(DCSRSPEC_EXT) {
            let mut hsm = Hsm::new(
                0x0002,
                // TODO: this will probably not work
                // This assumes that the OKM_HSM_PKCS11_AUTH env var has
                // already been set up. When this code was in the ca module
                // that was true but it may not be here.
                &passwd_from_env("OKM_HSM_PKCS11_AUTH")?,
                out.as_ref(),
                state.as_ref(),
                false,
                transport,
            )?;
            (DCSR_SUFFIX, sign_dcsrspec(path, cas, &mut hsm)?)
        } else {
            return Err(anyhow!("Unknown input spec: {}", path.display()));
        };

        let path =
            PathBuf::from(out.as_ref()).join(format!("{}.{}", prefix, suffix));
        debug!("writing credential to: {}", path.display());
        std::fs::write(path, &data)?;
    }

    Ok(())
}

// TODO: this is sketchy ... likely an artifact of bad / no design
fn passwd_from_env(env_str: &str) -> Result<String> {
    Ok(env::var(env_str)?
            .strip_prefix("0002")
            .ok_or_else(|| anyhow!("Missing key identifier prefix in environment variable \"{env_str}\" that is expected to contain an HSM password"))?
            .to_string()
        )
}

fn main() -> Result<()> {
    let args = Args::parse();

    let mut builder = Builder::from_default_env();

    let level = if args.verbose {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };
    builder.filter(None, level).init();

    make_dir(&args.output)?;
    make_dir(&args.state)?;

    match args.command {
        Command::Ca { command } => match command {
            CaCommand::Initialize {
                key_spec,
                pkcs11_path,
            } => {
                let _ = initialize_all_ca(
                    &key_spec,
                    &pkcs11_path,
                    &args.state,
                    &args.output,
                )?;
                Ok(())
            }
            CaCommand::Sign { csr_spec } => {
                let cas = load_all_ca(&args.state)?;
                sign_all(
                    &cas,
                    &csr_spec,
                    &args.state,
                    &args.output,
                    args.transport,
                )
            }
        },
        Command::Hsm {
            auth_id,
            command,
            no_backup,
        } => {
            let passwd = get_passwd(auth_id, &command)?;
            let auth_id = get_auth_id(auth_id, &command);
            let mut hsm = Hsm::new(
                auth_id,
                &passwd,
                &args.output,
                &args.state,
                !no_backup,
                args.transport,
            )?;

            match command {
                HsmCommand::Initialize {
                    print_dev,
                    passwd_challenge,
                } => {
                    debug!("Initialize");
                    let (shares, verifier) = hsm.new_split_wrap()?;
                    let verifier = serde_json::to_string(&verifier)?;
                    debug!("JSON: {}", verifier);
                    let verifier_path = args.output.join(VERIFIER_FILE);
                    debug!(
                        "Serializing verifier as json to: {}",
                        verifier_path.display()
                    );

                    fs::write(verifier_path, verifier)?;

                    println!(
                        "\nWARNING: The wrap / backup key has been created and stored in the\n\
                        YubiHSM. It will now be split into {} key shares and each share\n\
                        will be individually written to {}. Before each keyshare is\n\
                        printed, the operator will be prompted to ensure the appropriate key\n\
                        custodian is present in front of the printer.\n\n\
                        Press enter to begin the key share recording process ...",
                        LIMIT,
                        print_dev.display(),
                    );

                    let secret_writer =
                        PrinterSecretWriter::new(Some(&print_dev));
                    for (i, share) in shares.as_ref().iter().enumerate() {
                        let share_num = i + 1;
                        println!(
                            "When key custodian {num} is ready, press enter to print share \
                            {num}",
                            num = share_num,
                        );
                        util::wait_for_line()?;

                        // TODO: ergonomics?
                        // we're iterating over &Share so we've gotta clone it to wrap it
                        // in a `Zeroize` like `share` expects
                        secret_writer.share(
                            i,
                            LIMIT,
                            &Zeroizing::new(*share),
                        )?;
                        println!(
                            "When key custodian {} has collected their key share, press enter",
                            share_num,
                        );
                        util::wait_for_line()?;
                    }
                    let passwd_new = if passwd_challenge {
                        get_new_passwd(None)?
                    } else {
                        get_new_passwd(Some(&hsm))?
                    };

                    let secret_writer =
                        PrinterSecretWriter::new(Some(&print_dev));
                    secret_writer.password(&passwd_new)?;

                    hsm.dump_attest_cert::<String>(None)?;
                    hsm.replace_default_auth(&passwd_new)
                }
                HsmCommand::Generate { key_spec } => hsm.generate(&key_spec),
                HsmCommand::Restore { backups, verifier } => {
                    let verifier = fs::read_to_string(verifier)?;
                    let verifier: Verifier = serde_json::from_str(&verifier)?;
                    let share_itr = StdioShareReader::new(verifier);

                    let mut shares: Zeroizing<Vec<Share>> =
                        Zeroizing::new(Vec::new());
                    for share in share_itr {
                        shares.deref_mut().push(*share?.deref());
                        if shares.len() >= THRESHOLD {
                            break;
                        }
                    }

                    hsm.restore_wrap(shares)?;
                    oks::hsm::restore(&hsm.client, backups)?;
                    info!("Deleting default authentication key");
                    oks::hsm::delete(&hsm.client, 1, Type::AuthenticationKey)
                }
                HsmCommand::SerialNumber => oks::hsm::dump_sn(&hsm.client),
            }
        }
        Command::Ceremony {
            ref csr_spec,
            ref key_spec,
            ref pkcs11_path,
            ref print_dev,
            passwd_challenge,
        } => do_ceremony(
            csr_spec,
            key_spec,
            pkcs11_path,
            print_dev,
            passwd_challenge,
            &args,
        ),
    }
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{Context, Result};
use clap::{builder::ArgPredicate, Args, ValueEnum};
use glob::Paths;
use log::debug;
use std::{
    env,
    ffi::OsStr,
    io::{self, Read, Write},
    ops::Deref,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

use crate::{
    backup::{Share, Verifier},
    cdrw::{CdReader, IsoReader},
};

#[derive(ValueEnum, Copy, Clone, Debug, Default, PartialEq)]
pub enum SecretInput {
    Cdr,
    Iso,
    #[default]
    Stdio,
}

impl From<SecretInput> for ArgPredicate {
    fn from(val: SecretInput) -> Self {
        let rep = match val {
            SecretInput::Cdr => SecretInput::Cdr.into(),
            SecretInput::Iso => SecretInput::Iso.into(),
            SecretInput::Stdio => SecretInput::Stdio.into(),
        };
        ArgPredicate::Equals(OsStr::new(rep).into())
    }
}

impl From<SecretInput> for &str {
    fn from(val: SecretInput) -> &'static str {
        match val {
            SecretInput::Cdr => "cdr",
            SecretInput::Iso => "iso",
            SecretInput::Stdio => "stdio",
        }
    }
}

// thread 'main' panicked at /home/flihp/.cargo/registry/src/index.crates.io-6f17d22bba15001f/clap_builder-4.5.18/src/builder/debug_asserts.rs:86:13:
// Command change-auth: Argument names must be unique, but 'method' is in use by more than one argument or group
// note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
#[derive(Args, Clone, Debug, Default, PartialEq)]
pub struct AuthInputArg {
    #[clap(long, env)]
    auth_method: SecretInput,

    #[clap(long, env)]
    auth_device: Option<PathBuf>,
}

pub trait PasswordReader {
    fn read(&mut self, prompt: &str) -> Result<Zeroizing<String>>;
}

pub fn get_passwd_reader(
    input: &AuthInputArg,
) -> Result<Box<dyn PasswordReader>> {
    Ok(match input.auth_method {
        SecretInput::Cdr => {
            let cdr = CdReader::new(input.auth_device.as_ref());
            Box::new(CdrPasswordReader::new(cdr))
        }
        SecretInput::Iso => {
            Box::new(IsoPasswordReader::new(input.auth_device.as_ref())?)
        }
        SecretInput::Stdio => Box::new(StdioPasswordReader {}),
    })
}

#[derive(Default)]
pub struct StdioPasswordReader {}

impl PasswordReader for StdioPasswordReader {
    fn read(&mut self, prompt: &str) -> Result<Zeroizing<String>> {
        Ok(Zeroizing::new(rpassword::prompt_password(prompt)?))
    }
}

struct IsoPasswordReader {
    iso: IsoReader,
}

impl IsoPasswordReader {
    pub fn new<P: AsRef<Path>>(iso: Option<P>) -> Result<Self> {
        let iso = match iso {
            None => {
                let pwd = env::current_dir().context("Failed to get PWD")?;
                pwd.join("password.iso")
            }
            Some(i) => i.as_ref().to_path_buf(),
        };

        Ok(Self {
            iso: IsoReader::new(iso),
        })
    }
}

impl PasswordReader for IsoPasswordReader {
    fn read(&mut self, _prompt: &str) -> Result<Zeroizing<String>> {
        let password =
            Zeroizing::new(String::from_utf8(self.iso.read("password")?)?);
        debug!("read password: {:?}", password.deref());

        Ok(password)
    }
}

pub struct CdrPasswordReader {
    cdr: CdReader,
}

impl CdrPasswordReader {
    pub fn new(cdr: CdReader) -> Self {
        Self { cdr }
    }
}

impl PasswordReader for CdrPasswordReader {
    fn read(&mut self, _prompt: &str) -> Result<Zeroizing<String>> {
        let password = self.cdr.read("password")?;

        // Passwords are utf8 and `String::from_utf8` explicitly does *not*
        // copy the Vec<u8>.
        let password = Zeroizing::new(String::from_utf8(password)?);
        debug!("read password: {:?}", password.deref());

        Ok(password)
    }
}

#[derive(Args, Clone, Debug, Default, PartialEq)]
pub struct ShareInputArg {
    #[clap(long = "share-method", env)]
    method: SecretInput,

    #[clap(long = "share-device", env)]
    device: Option<PathBuf>,
}

pub fn get_share_reader(
    input: &ShareInputArg,
    verifier: Verifier,
) -> Result<Box<dyn Iterator<Item = Result<Zeroizing<Share>>>>> {
    Ok(match input.method {
        SecretInput::Cdr => {
            let cdr = CdReader::new(input.device.as_ref());
            Box::new(CdrShareReader::new(cdr, verifier))
        }
        SecretInput::Iso => {
            Box::new(IsoShareReader::new(input.device.as_ref(), verifier)?)
        }
        SecretInput::Stdio => Box::new(StdioShareReader::new(verifier)),
    })
}

// ShareReader require a verifier. We separate ShareReaders from from
// PasswordReaders because we need to create PasswordReaders in
// situations when we don't have a reader.
pub struct StdioShareReader {
    verifier: Verifier,
}

impl StdioShareReader {
    pub fn new(verifier: Verifier) -> Self {
        Self { verifier }
    }
}

impl Iterator for StdioShareReader {
    type Item = Result<Zeroizing<Share>>;

    fn next(&mut self) -> Option<Self::Item> {
        // get share from stdin
        loop {
            // clear the screen, move cursor to (0,0), & prompt user
            print!("\x1B[2J\x1B[1;1H");
            print!("Enter share\n: ");
            match io::stdout().flush() {
                Ok(()) => (),
                Err(e) => return Some(Err(e.into())),
            }

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
                        match io::stdout().flush() {
                            Ok(()) => (),
                            Err(e) => return Some(Err(e.into())),
                        }

                        // wait for a keypress / 1 byte from stdin
                        match io::stdin().read_exact(&mut [0u8]) {
                            Ok(_) => (),
                            Err(e) => return Some(Err(e.into())),
                        };
                        continue;
                    }
                },
                Err(e) => {
                    print!(
                        "Error from `Stdin::read_line`: {}\n\n\
                        Press any key to try again ...",
                        e
                    );
                    match io::stdout().flush() {
                        Ok(_) => (),
                        Err(e) => return Some(Err(e.into())),
                    }

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
            let share = match Share::try_from(&share_vec[..]) {
                Ok(share) => Zeroizing::new(share),
                Err(_) => {
                    println!(
                        "Failed to convert share entered to the Share type.\n\
                        The value entered is the wrong length ... try again."
                    );
                    continue;
                }
            };

            let verified = match verify(&self.verifier, &share) {
                Ok(v) => v,
                Err(e) => return Some(Err(e)),
            };

            if verified {
                break Some(Ok(share));
            }
        }
    }
}

struct IsoShareReader {
    globs: Paths,
    verifier: Verifier,
}

const SHARE_ISO_GLOB: &str = "share_*-of-*.iso";

impl IsoShareReader {
    pub fn new<P: AsRef<Path>>(
        dir: Option<P>,
        verifier: Verifier,
    ) -> Result<Self> {
        let dir = match dir {
            None => env::current_dir().context("Failed to get PWD")?,
            Some(d) => d.as_ref().to_path_buf(),
        };

        let globs = glob::glob(
            dir.join(SHARE_ISO_GLOB)
                .to_str()
                .context("path can't be represented as an str")?,
        )
        .context(format!("Invalid Glob: {}", SHARE_ISO_GLOB))?;

        Ok(Self { globs, verifier })
    }
}

impl Iterator for IsoShareReader {
    type Item = Result<Zeroizing<Share>>;

    fn next(&mut self) -> Option<Self::Item> {
        let share_iso = match self.globs.next() {
            None => {
                debug!("no globs left");
                return None;
            }
            Some(r) => match r {
                Ok(iso) => iso,
                Err(e) => return Some(Err(e.into())),
            },
        };

        debug!("getting share from ISO: {}", share_iso.display());
        let iso = IsoReader::new(share_iso);

        let share = match iso.read("share") {
            Err(e) => return Some(Err(e)),
            Ok(s) => s,
        };

        let share = match Share::try_from(&share[..]) {
            Ok(s) => Zeroizing::new(s),
            Err(e) => return Some(Err(e.into())),
        };

        match verify(&self.verifier, &share) {
            Ok(v) => {
                if v {
                    Some(Ok(share))
                } else {
                    Some(Err(anyhow::anyhow!("verification failed")))
                }
            }
            Err(e) => Some(Err(e)),
        }
    }
}

pub struct CdrShareReader {
    cdr: CdReader,
    verifier: Verifier,
}

impl CdrShareReader {
    pub fn new(cdr: CdReader, verifier: Verifier) -> Self {
        Self { cdr, verifier }
    }
}

impl Iterator for CdrShareReader {
    type Item = Result<Zeroizing<Share>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.cdr.eject() {
            Ok(()) => (),
            Err(e) => return Some(Err(e)),
        }

        print!(
            "Place keyshare CD in the drive, close the drive, then press \n\
               any key to continue: "
        );
        match io::stdout().flush() {
            Ok(()) => (),
            Err(e) => return Some(Err(e.into())),
        }
        // wait for user input
        match io::stdin().read_exact(&mut [0u8]) {
            Ok(_) => (),
            Err(e) => return Some(Err(e.into())),
        };

        let share = match self.cdr.read("share") {
            Ok(b) => b,
            Err(e) => return Some(Err(e)),
        };
        println!("\nOK");

        let share = match Share::try_from(share.deref()) {
            Ok(s) => Zeroizing::new(s),
            Err(e) => return Some(Err(e.into())),
        };

        match verify(&self.verifier, &share) {
            Ok(b) => {
                if b {
                    Some(Ok(share))
                } else {
                    Some(Err(anyhow::anyhow!("verification failed")))
                }
            }
            Err(e) => Some(Err(e)),
        }
    }
}

fn verify(verifier: &Verifier, share: &Zeroizing<Share>) -> Result<bool> {
    if verifier.verify(share.deref()) {
        print!("\nShare verified!\n\nPress any key to continue ...");
        io::stdout().flush()?;

        // wait for a keypress / 1 byte from stdin
        let _ = io::stdin().read(&mut [0u8]).unwrap();
        print!("\x1B[2J\x1B[1;1H");
        Ok(true)
    } else {
        print!(
            "\nFailed to verify share :(\n\nPress any key to \
            try again ..."
        );
        io::stdout().flush()?;

        // wait for a keypress / 1 byte from stdin
        let _ = io::stdin().read(&mut [0u8]).unwrap();
        Ok(false)
    }
}

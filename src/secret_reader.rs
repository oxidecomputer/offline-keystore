// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use clap::{builder::ArgPredicate, Args, ValueEnum};
use log::debug;
use std::{
    ffi::OsStr,
    io::{self, Read, Write},
    ops::Deref,
    path::PathBuf,
};
use zeroize::Zeroizing;

use crate::{
    backup::{Share, Verifier},
    cdrw::Cdr,
};

#[derive(Args, Clone, Debug, Default, PartialEq)]
pub struct SecretInputArg {
    #[clap(long, env)]
    auth_method: SecretInput,

    #[clap(long, env)]
    auth_dev: Option<PathBuf>,
}

#[derive(ValueEnum, Copy, Clone, Debug, Default, PartialEq)]
pub enum SecretInput {
    Cdr,
    #[default]
    Stdio,
}

impl From<SecretInput> for ArgPredicate {
    fn from(val: SecretInput) -> Self {
        let rep = match val {
            SecretInput::Cdr => SecretInput::Cdr.into(),
            SecretInput::Stdio => SecretInput::Stdio.into(),
        };
        ArgPredicate::Equals(OsStr::new(rep).into())
    }
}

impl From<SecretInput> for &str {
    fn from(val: SecretInput) -> &'static str {
        match val {
            SecretInput::Cdr => "cdr",
            SecretInput::Stdio => "stdio",
        }
    }
}

pub trait PasswordReader {
    fn read(&mut self, prompt: &str) -> Result<Zeroizing<String>>;
}

pub fn get_passwd_reader(
    input: &SecretInputArg,
) -> Result<Box<dyn PasswordReader>> {
    Ok(match input.auth_method {
        SecretInput::Stdio => Box::new(StdioPasswordReader {}),
        SecretInput::Cdr => {
            let cdr = Cdr::new(input.auth_dev.as_ref())?;
            Box::new(CdrPasswordReader::new(cdr))
        }
    })
}

#[derive(Default)]
pub struct StdioPasswordReader {}

impl PasswordReader for StdioPasswordReader {
    fn read(&mut self, prompt: &str) -> Result<Zeroizing<String>> {
        Ok(Zeroizing::new(rpassword::prompt_password(prompt)?))
    }
}

pub fn get_share_reader(
    input: &SecretInputArg,
    verifier: Verifier,
) -> Result<Box<dyn Iterator<Item = Result<Zeroizing<Share>>>>> {
    Ok(match input.auth_method {
        SecretInput::Stdio => Box::new(StdioShareReader::new(verifier)),
        SecretInput::Cdr => {
            let cdr = Cdr::new(input.auth_dev.as_ref())?;
            Box::new(CdrShareReader::new(cdr, verifier))
        }
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

pub struct CdrPasswordReader {
    cdr: Cdr,
}

impl CdrPasswordReader {
    pub fn new(cdr: Cdr) -> Self {
        Self { cdr }
    }
}

impl PasswordReader for CdrPasswordReader {
    // TODO: figure out user interaction / prompt stuff
    // TODO: if this were to consume `self` we may be able to make
    // `Cdr::teardown` do the same ...
    fn read(&mut self, _prompt: &str) -> Result<Zeroizing<String>> {
        self.cdr.mount()?;

        let password = self.cdr.read("password")?;

        // Passwords are utf8 and `String::from_utf8` explicitly does *not*
        // copy the Vec<u8>.
        let password = Zeroizing::new(String::from_utf8(password)?);
        debug!("read password: {:?}", password.deref());
        self.cdr.teardown();

        Ok(password)
    }
}

pub struct CdrShareReader {
    cdr: Cdr,
    verifier: Verifier,
}

impl CdrShareReader {
    pub fn new(cdr: Cdr, verifier: Verifier) -> Self {
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

        // TODO: retry loop
        // a drive tested errors out very quickly if the drive is still
        // reading the disk, another will just block until data is ready
        // ¯\_(ツ)_/¯
        match self.cdr.mount() {
            Ok(()) => (),
            Err(e) => return Some(Err(e)),
        }
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

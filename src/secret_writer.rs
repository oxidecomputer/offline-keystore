// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use hex::ToHex;
use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

use crate::{hsm::Share, util};

pub const DEFAULT_PRINT_DEV: &str = "/dev/usb/lp0";

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

/// This type exports secrets by writing them to a printer.
/// This has only been tested with an Epson ESC/P.
pub struct PrinterSecretWriter {
    device: PathBuf,
}

impl PrinterSecretWriter {
    pub fn new<P: AsRef<Path>>(device: Option<P>) -> Self {
        let device = match device {
            None => PathBuf::from(DEFAULT_PRINT_DEV),
            Some(p) => p.as_ref().to_path_buf(),
        };

        Self { device }
    }

    pub fn password(&self, password: &Zeroizing<String>) -> Result<()> {
        println!(
            "\nWARNING: The HSM authentication password has been created and stored in\n\
            the YubiHSM. It will now be printed to {}.\n\
            Before this password is printed, the operator will be prompted to ensure\n\
            that the appropriate participant is in front of the printer to recieve\n\
            the printout.\n\n\
            Press enter to print the HSM password ...",
            self.device.display(),
        );

        util::wait_for_line()?;

        let mut print_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.device)?;

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
            CR, LF, ESC, b'F', // Deselect Bold
        ])?;
        print_centered_line(&mut print_file, b"HSM Password")?;
        print_file.write_all(&[
            CR, LF, CR, LF, ESC, b'D', 8, 20, 32, 44,
            0, // Set horizontal tab stops
            CR, LF,
        ])?;

        for (i, chunk) in password.as_bytes().chunks(8).enumerate() {
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

    pub fn share(
        &self,
        index: usize,
        limit: usize,
        share: &Zeroizing<Share>,
    ) -> Result<()> {
        // ESC/P specification recommends sending CR before LF and FF. The
        // latter commands print the contents of the data buffer before their
        // movement. This can cause double printing (bolding) in certain
        // situations. Sending CR clears the data buffer without printing so
        // sending it first avoids any double printing.
        let mut print_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.device)?;

        print_file.write_all(&[
            ESC, b'@', // Initialize Printer
            ESC, b'x', 1, // Select NLQ mode
            ESC, b'k', 1, // Select San Serif font
            ESC, b'E', // Select Bold
        ])?;
        print_centered_line(&mut print_file, b"Oxide Offline Keystore")?;
        print_file.write_all(&[
            CR, LF, ESC, b'F', // Deselect Bold
        ])?;

        print_centered_line(
            &mut print_file,
            format!("Recovery Key Share {} of {}", index + 1, limit).as_bytes(),
        )?;
        print_file.write_all(&[
            CR, LF, CR, LF, ESC, b'D', 8, 20, 32, 44,
            0, // Set horizontal tab stops
        ])?;

        for (i, chunk) in share
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

        print_whitespace_notice(&mut print_file, "recovery key share")?;

        print_file.write_all(&[CR, FF])?;
        Ok(())
    }
}

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

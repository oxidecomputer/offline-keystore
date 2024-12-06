// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use hex::ToHex;
use oks::{
    alphabet::Alphabet,
    backup::Share,
    secret_writer::{PrinterSecretWriter, SecretWriter},
};
use rand::thread_rng;
use zeroize::Zeroizing;

#[derive(Parser)]
struct Args {
    #[clap(long, env, default_value = "/dev/usb/lp0")]
    print_dev: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    RecoveryKeyShare {
        #[clap(default_value_t = 1)]
        share_idx: usize,
        #[clap(default_value_t = 5)]
        share_count: usize,
        #[clap(default_value_t = 33)]
        data_len: usize,
    },
    HsmPassword {
        #[clap(default_value_t = 16)]
        length: usize,
    },
}

fn main() -> Result<()> {
    let args = Args::parse();
    let secret_writer = PrinterSecretWriter::new(Some(args.print_dev));

    match args.command {
        Command::RecoveryKeyShare {
            share_idx,
            share_count,
            data_len,
        } => {
            let share_data: Vec<u8> =
                (0..data_len).map(|x| (x % 256) as u8).collect();
            let share = Share::try_from(&share_data[..])?;
            let share = Zeroizing::new(share);

            println!("Data: {}", share_data.encode_hex::<String>());

            secret_writer.share(share_idx, share_count, &share)
        }
        Command::HsmPassword { length } => {
            let mut rng = thread_rng();
            let password =
                Alphabet::new().get_random_string(&mut rng, length)?;
            let password = Zeroizing::new(password);
            secret_writer.password(&password)
        }
    }
}

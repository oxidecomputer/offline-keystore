// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{fs::OpenOptions, path::PathBuf};

use anyhow::Result;
use clap::{Parser, Subcommand};
use hex::ToHex;
use oks::hsm::Alphabet;
use rand::{thread_rng, Rng};
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

    match args.command {
        Command::RecoveryKeyShare {
            share_idx,
            share_count,
            data_len,
        } => {
            let mut print_file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(args.print_dev)?;

            let share_data: Vec<u8> =
                (0..data_len).map(|x| (x % 256) as u8).collect();

            println!("Data: {}", share_data.encode_hex::<String>());

            oks::hsm::print_share(
                &mut print_file,
                share_idx,
                share_count,
                &share_data,
            )
        }
        Command::HsmPassword { length } => {
            let password = Alphabet::new()
                .get_random_string(|| Ok(thread_rng().gen::<u8>()), length)?;
            let password = Zeroizing::new(password);
            oks::hsm::print_password(&args.print_dev, &password)
        }
    }
}

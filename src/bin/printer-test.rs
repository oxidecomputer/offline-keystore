// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{fs::OpenOptions, path::PathBuf};

use anyhow::Result;
use clap::{Parser, Subcommand};
use hex::ToHex;

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
        share_idx: usize,
        share_count: usize,
        data_len: usize,
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
    }
}

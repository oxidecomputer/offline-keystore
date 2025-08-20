// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Context;
use clap::{Parser, ValueEnum};
use lpc55_areas::{DebugFieldSetting, DebugSettings};
use lpc55_sign::debug_auth::DebugCredentialSigningRequest;
use rsa::{pkcs8::DecodePublicKey, RsaPublicKey};
use std::{
    fs::File,
    io::{self, Read, Write},
    path::PathBuf,
};

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Profile {
    BootlebyImageSelection,
    PlatformIdentityProgramming,
    PostSecretScrub,
    PreSecretScrub,
}

const DISABLED_SETTINGS: DebugSettings = DebugSettings {
    non_invasive_debug: DebugFieldSetting::AlwaysDisabled,
    invasive_debug: DebugFieldSetting::AlwaysDisabled,
    secure_non_invasive_debug: DebugFieldSetting::AlwaysDisabled,
    secure_invasive_debug: DebugFieldSetting::AlwaysDisabled,
    cpu1_dbg_enable: DebugFieldSetting::AlwaysDisabled,
    cpu1_non_invasive_enable: DebugFieldSetting::AlwaysDisabled,
    tap_enable: DebugFieldSetting::AlwaysDisabled,
    isp_enable: DebugFieldSetting::AlwaysDisabled,
    fa_me_enable: DebugFieldSetting::AlwaysDisabled,
    uuid_check: false,
};

const BOOTLEBY_IMAGE_SELECTION_SETTINGS: DebugSettings = DISABLED_SETTINGS;

const PLATFORM_IDENTITY_PROGRAMMING_SETTINGS: DebugSettings = DISABLED_SETTINGS;

const POST_SECRET_SCRUB_SETTINGS: DebugSettings = DebugSettings {
    non_invasive_debug: DebugFieldSetting::DebugAuth,
    invasive_debug: DebugFieldSetting::DebugAuth,
    secure_non_invasive_debug: DebugFieldSetting::DebugAuth,
    secure_invasive_debug: DebugFieldSetting::DebugAuth,
    cpu1_dbg_enable: DebugFieldSetting::AlwaysDisabled,
    cpu1_non_invasive_enable: DebugFieldSetting::AlwaysDisabled,
    tap_enable: DebugFieldSetting::AlwaysDisabled,
    isp_enable: DebugFieldSetting::AlwaysDisabled,
    fa_me_enable: DebugFieldSetting::AlwaysDisabled,
    uuid_check: false,
};

const PRE_SECRET_SCRUB_SETTINGS: DebugSettings = DebugSettings {
    non_invasive_debug: DebugFieldSetting::DebugAuth,
    invasive_debug: DebugFieldSetting::DebugAuth,
    secure_non_invasive_debug: DebugFieldSetting::DebugAuth,
    secure_invasive_debug: DebugFieldSetting::DebugAuth,
    cpu1_dbg_enable: DebugFieldSetting::DebugAuth,
    cpu1_non_invasive_enable: DebugFieldSetting::DebugAuth,
    tap_enable: DebugFieldSetting::AlwaysDisabled,
    isp_enable: DebugFieldSetting::DebugAuth,
    fa_me_enable: DebugFieldSetting::AlwaysDisabled,
    uuid_check: false,
};

impl Profile {
    /// We do not generate UUID specific debug auth credentials. This returns
    /// all zeros
    fn uuid(&self) -> [u8; 16] {
        [0u8; 16]
    }

    /// We do not set the vendor usage field. This returns 0.
    fn vendor_usage(&self) -> u32 {
        0
    }

    /// Map `Profile` to OANA beacon values
    fn beacon(&self) -> u16 {
        match self {
            Profile::BootlebyImageSelection => 18578,
            Profile::PlatformIdentityProgramming => 53710,
            Profile::PostSecretScrub => 1000,
            Profile::PreSecretScrub => 0,
        }
    }

    /// Map `Profile` to `DebugSettings` per RFD 333
    fn debug_settings(&self) -> DebugSettings {
        match self {
            Profile::BootlebyImageSelection => {
                BOOTLEBY_IMAGE_SELECTION_SETTINGS
            }
            Profile::PlatformIdentityProgramming => {
                PLATFORM_IDENTITY_PROGRAMMING_SETTINGS
            }
            Profile::PostSecretScrub => POST_SECRET_SCRUB_SETTINGS,
            Profile::PreSecretScrub => PRE_SECRET_SCRUB_SETTINGS,
        }
    }
}

/// Generate a Debug Credential Signing Request
#[derive(Parser, Debug)]
struct Args {
    /// output path for generated DCSR, stdout if omitted
    #[clap(long)]
    out: Option<PathBuf>,

    /// debug authentication credential profile
    #[arg(value_enum)]
    profile: Profile,

    /// path to RSA public key as SPKI, stdin if omitted
    public_key: Option<PathBuf>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // get a reader appropriate to the input method
    let reader: Box<dyn Read> = match args.public_key {
        Some(ref i) => Box::new(File::open(i)?),
        None => Box::new(io::stdin()),
    };

    // read public key from file
    let pem = io::read_to_string(reader).with_context(|| {
        let src = match args.public_key {
            Some(ref i) => format!("{}", i.display()),
            None => "stdin".to_string(),
        };
        format!("reading public key from: {src}")
    })?;

    // transform public key from PEM encoded SPKI to `RsaPublicKey`
    let debug_public_key = RsaPublicKey::from_public_key_pem(&pem)
        .context("parsing RSA public key from SPKI")?;

    // create `DebugCredentialSigningRequest` from the provided public key &
    // debug authentication credential profile
    let dcsr = DebugCredentialSigningRequest {
        debug_public_key,
        uuid: args.profile.uuid(),
        vendor_usage: args.profile.vendor_usage(),
        debug_settings: args.profile.debug_settings(),
        beacon: args.profile.beacon(),
    };

    // get a writer appropriate to the output method
    let mut writer: Box<dyn Write> = match args.out {
        Some(o) => Box::new(File::create(o)?),
        None => Box::new(io::stdout()),
    };

    // output DCSR as pretty JSON
    serde_json::to_writer_pretty(&mut writer, &dcsr)
        .context("failed to write DCSR to writer")
}

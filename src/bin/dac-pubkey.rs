// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use rsa::{
    pkcs1::{EncodeRsaPublicKey, LineEnding},
    pkcs1v15::{Signature, VerifyingKey},
    pkcs8::EncodePublicKey,
    sha2::{Digest, Sha256},
    signature::DigestVerifier,
    BigUint, RsaPublicKey,
};
use std::{
    fs,
    io::{self, Write},
    path::PathBuf,
};
use zerocopy::{FromBytes, LittleEndian, U16, U32};

#[derive(Debug, FromBytes)]
#[repr(C)]
// This structure is described in UM11126 §51.7 and is specific to RSA 4k
// keys.
struct DebugCredentialCertificate {
    // first 2 bytes of VERSION
    pub version_major: U16<LittleEndian>,
    // second 2 bytes of VERSION
    pub version_minor: U16<LittleEndian>,
    // SOC class specifier
    pub soc_class_id: U32<LittleEndian>,
    // SOC UUID (uniquely identifies an SOC intance)
    pub uuid: [u8; 16],
    // RoT metadata uniquely identifying the CAs that authorize debug and
    // verified boot credentials
    pub rotmeta: [[u8; 32]; 4],
    // public part of RSA 4k key authorized by this debug credential cert to
    // sign debug auth challenges
    // NOTE: these are big endian byte streams
    pub debug_modulus: [u8; 512],
    pub debug_exponent: [u8; 4],
    // SoC specific Credential Constraint
    pub credential_constraint: U32<LittleEndian>,
    pub vendor_usage: U32<LittleEndian>,
    pub credential_beacon: U32<LittleEndian>,
    // public part of RSA 4k key acting as a trust anchor on the LPC55 platform
    // NOTE: these are big endian byte streams
    pub rotk_modulus: [u8; 512],
    pub rotk_exponent: [u8; 4],
    // RSA-SSA PKCS#1 v1.5 signature
    pub signature: [u8; 512],
}

#[derive(ValueEnum, Copy, Clone, Debug, Default)]
enum Format {
    Pkcs1,
    #[default]
    Spki,
}

#[derive(ValueEnum, Copy, Clone, Debug, Default)]
enum Encoding {
    Der,
    #[default]
    Pem,
}

#[derive(ValueEnum, Copy, Clone, Debug, Default)]
enum PublicKey {
    #[default]
    Dck,
    Rotk,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// extract and transcode a public key from the DC
    Pubkey {
        /// The public key to extract
        #[clap(default_value_t, long, value_enum)]
        kind: PublicKey,

        /// The encoding used to serialize the public key.
        #[clap(default_value_t, long, value_enum)]
        encoding: Encoding,

        /// The format use to represent the public key.
        #[clap(default_value_t, long, value_enum)]
        format: Format,
    },
    Verify,
}

/// Extract and transcode the RSA public keys from an Lpc55 debug
/// credential certificate (DC).
#[derive(Parser, Debug)]
struct Args {
    #[command(subcommand)]
    command: Command,

    /// Path to signed debug auth credential file
    dc_file: PathBuf,
}

fn pubkey_out(
    pub_key: &RsaPublicKey,
    encoding: Encoding,
    format: Format,
) -> Result<()> {
    match encoding {
        Encoding::Der => {
            let der = match format {
                Format::Pkcs1 => pub_key.to_pkcs1_der().context(
                    "Get DER encoded, PKCS#1 formatted RSA public key",
                )?,
                Format::Spki => pub_key.to_public_key_der().context(
                    "Get DER encoded, SPKI formatted RSA public key",
                )?,
            };
            io::stdout()
                .write_all(der.as_bytes())
                .context("write encoded public key to stdout")
        }
        Encoding::Pem => {
            let pem = match format {
                Format::Pkcs1 => pub_key
                    .to_pkcs1_pem(LineEnding::default())
                    .context("Get PEM encoded PKCS#1 from RSA public key")?,
                Format::Spki => pub_key
                    .to_public_key_pem(LineEnding::default())
                    .context("Get SPKI PEM from RSA public key")?,
            };
            io::stdout()
                .write_all(pem.as_bytes())
                .context("write encoded public key to stdout")
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    let dc_bytes = fs::read(&args.dc_file).with_context(|| {
        format!("Reading debug cert file: {}", args.dc_file.display())
    })?;

    let (dc, remain) =
        match DebugCredentialCertificate::read_from_prefix(dc_bytes.as_slice())
        {
            Ok((dc, remain)) => (dc, remain),
            Err(_) => {
                return Err(anyhow!("Failed to parse debug auth credential"))
            }
        };

    if !remain.is_empty() {
        return Err(anyhow!(
            "Failed to parse debug cert: {} bytes left over",
            remain.len()
        ));
    }

    if !(dc.version_major == 1 && dc.version_minor == 1) {
        return Err(anyhow!(
            "Unsupported debug cert version: {}.{}",
            dc.version_major,
            dc.version_minor
        ));
    }

    match args.command {
        Command::Pubkey {
            kind,
            encoding,
            format,
        } => {
            let (n, e) = match kind {
                PublicKey::Dck => (&dc.debug_modulus, &dc.debug_exponent),
                PublicKey::Rotk => (&dc.rotk_modulus, &dc.rotk_exponent),
            };

            let pub_key = RsaPublicKey::new(
                BigUint::from_bytes_be(n),
                BigUint::from_bytes_be(e),
            )
            .context("Extracting RSA public key from debug cert")?;

            pubkey_out(&pub_key, encoding, format)
        }
        Command::Verify => {
            let sig = Signature::try_from(&dc.signature[..]).context(
                "Extracting RSASSA-PKCS1-v1_5 signature from debug cert",
            )?;

            // reconstruct the sha256 digest of the message that was signed
            let tbs_offset = dc_bytes.len() - dc.signature.len();
            let mut digest = Sha256::new();
            digest.update(&dc_bytes[..tbs_offset]);
            let digest = digest;

            let pub_key = RsaPublicKey::new(
                BigUint::from_bytes_be(&dc.rotk_modulus),
                BigUint::from_bytes_be(&dc.rotk_exponent),
            )
            .context("Extracting RSA public key for RoTK from debug cert")?;

            let verifier = VerifyingKey::<Sha256>::new(pub_key);
            verifier
                .verify_digest(digest, &sig)
                .context("Verifying signature over debug cert against RoTK")
        }
    }
}

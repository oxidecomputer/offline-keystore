// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{Context, Result};
use log::{debug, warn};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use tempfile::{tempdir, TempDir};
use thiserror::Error;
use zeroize::Zeroizing;

pub const DEFAULT_CDRW_DEV: &str = "/dev/cdrom";

#[derive(Debug, Error)]
pub enum CdrwError {
    #[error("The device provided isn't a block dev or a regular file.")]
    BadDevice,

    #[error("Source directory is neither a file nor a directory.")]
    BadSrc,

    #[error("Failed to burn tmpdir to CDR device.")]
    BurnFail,

    #[error("Failed to eject Cdr.")]
    EjectFail,

    #[error("Unable to get next available loopback device.")]
    GetLoopback,

    #[error("Failed to make ISO from state directory.")]
    IsoFail,

    #[error("Failed to mount Cdr.")]
    MountFail,
}

pub struct Cdr {
    device: PathBuf,
    tmpdir: TempDir,
    loopback: Option<PathBuf>,
}

impl Cdr {
    pub fn new<P: AsRef<Path>>(device: Option<P>) -> Result<Self> {
        let device = match device {
            Some(s) => PathBuf::from(s.as_ref()),
            None => PathBuf::from(DEFAULT_CDRW_DEV),
        };
        Ok(Self {
            device,
            tmpdir: tempdir()?,
            loopback: None,
        })
    }

    pub fn eject(&self) -> Result<()> {
        let mut cmd = Command::new("eject");
        let output = cmd.arg(&self.device).output().with_context(|| {
            format!("failed to run the \"eject\" command: \"{:?}\"", cmd)
        })?;

        if !output.status.success() {
            warn!("command failed with status: {}", output.status);
            warn!("stderr: \"{}\"", String::from_utf8_lossy(&output.stderr));
            return Err(CdrwError::EjectFail.into());
        }

        Ok(())
    }

    pub fn mount(&mut self) -> Result<()> {
        use std::os::unix::fs::FileTypeExt;
        // if self.device is a regular file assume it's an iso ... check
        // suffix too?
        // else if it's a device then just mount it
        // otherwise fail
        let file_type = self.device.metadata()?.file_type();
        if file_type.is_file() {
            // if we've been givn an ISO we need to setup a loopback device
            // checkout udisksctl?
            let mut cmd = Command::new("losetup");
            let output = cmd
                .arg("-f")
                .output()
                .with_context(|| "unable to execute \"losetup\"")?;

            debug!("executing command: \"{:#?}\"", cmd);

            if !output.status.success() {
                warn!("command failed with status: {}", output.status);
                warn!(
                    "stderr: \"{}\"",
                    String::from_utf8_lossy(&output.stderr)
                );
                return Err(CdrwError::GetLoopback.into());
            }
            // get path to the loopback device from `losetup` stdout
            let loop_dev =
                String::from(String::from_utf8(output.stdout)?.trim());
            debug!("got loopback device: {}", loop_dev);
            let loop_dev = PathBuf::from(loop_dev);

            let mut cmd = Command::new("losetup");
            let output = cmd
                .arg(&loop_dev)
                .arg(&self.device)
                .output()
                .with_context(|| "failed to execute \"losetup\"")?;

            debug!("executing command: \"{:#?}\"", cmd);
            if !output.status.success() {
                warn!("command failed with status: {}", output.status);
                warn!(
                    "stderr: \"{}\"",
                    String::from_utf8_lossy(&output.stderr)
                );
                return Err(CdrwError::GetLoopback.into());
            }

            self._mount(&loop_dev)?;
            self.loopback = Some(loop_dev);
        } else if file_type.is_block_device() {
            self._mount(&self.device)?;
        } else {
            return Err(CdrwError::BadDevice.into());
        }

        Ok(())
    }

    pub fn read(&self, name: &str) -> Result<Vec<u8>> {
        let path = self.tmpdir.as_ref().join(name);
        debug!("reading data from {}", path.display());

        fs::read(&path).with_context(|| {
            format!("failed to read file: {} from Cdr", path.display())
        })
    }

    // TODO: be resilient to device already mounted ...
    // iterate over Process::mountinfo?
    fn _mount<P: AsRef<Path>>(&self, device: &P) -> Result<()> {
        let mut cmd = Command::new("mount");
        let output = cmd
            .arg(device.as_ref())
            .arg(self.tmpdir.as_ref())
            .output()
            .with_context(|| {
                format!(
                    "failed to mount \"{}\" at \"{}\"",
                    device.as_ref().display(),
                    self.tmpdir.as_ref().display()
                )
            })?;

        if !output.status.success() {
            warn!("command failed with status: {}", output.status);
            warn!("stderr: \"{}\"", String::from_utf8_lossy(&output.stderr));
            return Err(CdrwError::MountFail.into());
        }

        Ok(())
    }

    // do this in `Drop`?
    pub fn teardown(&self) {
        // unmount self.tmpdir
        let mut cmd = Command::new("umount");
        // TODO: clone
        let output = cmd
            .arg(self.device.clone())
            .arg(self.tmpdir.as_ref())
            .output();
        let output = match output {
            Ok(o) => o,
            _ => {
                warn!(
                    "failed to unmount \"{}\"",
                    self.tmpdir.as_ref().display()
                );
                return;
            }
        };

        if !output.status.success() {
            warn!("command failed with status: {}", output.status);
            warn!("stderr: \"{}\"", String::from_utf8_lossy(&output.stderr));
            return;
        }

        if self.loopback.is_some() {
            let loopback = self.loopback.clone().unwrap();
            let mut cmd = Command::new("losetup");
            let output = cmd.arg("-d").arg(&loopback).output();

            let output = match output {
                Ok(o) => o,
                _ => {
                    warn!(
                        "failed to destroy loopback device {}",
                        loopback.display()
                    );
                    return;
                }
            };

            if !output.status.success() {
                warn!("command failed with status: {}", output.status);
                warn!(
                    "stderr: \"{}\"",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
    }
}

pub struct Cdw {
    tmp: TempDir,
    device: PathBuf,
}

impl Cdw {
    // If `device` is `None` then we will only create an iso and return the
    // bytes.
    pub fn new(device: Option<PathBuf>) -> Result<Cdw> {
        let device = device.unwrap_or_else(|| {
            // the error type return is infallible
            PathBuf::from(DEFAULT_CDRW_DEV)
        });
        Ok(Self {
            device,
            tmp: tempdir()?,
        })
    }

    pub fn add<P: AsRef<Path>>(&self, src: &P) -> Result<()> {
        let name = src.as_ref().file_name().ok_or(CdrwError::BadSrc)?;
        let dst = self.tmp.path().join(name);

        let _ = fs::copy(src, &dst).context(format!(
            "Failed to copy source \"{}\" to destination \"{}\"",
            src.as_ref().display(),
            dst.display()
        ))?;
        Ok(())
    }

    pub fn write_password(&self, data: &Zeroizing<String>) -> Result<()> {
        let path = self.tmp.as_ref().join("password");
        debug!(
            "Writing password: {} to: {}",
            <Zeroizing<String> as AsRef<str>>::as_ref(data),
            path.display()
        );

        Ok(fs::write(path, data)?)
    }

    pub fn write_share(&self, data: &[u8]) -> Result<()> {
        let path = self.tmp.as_ref().join("share");
        debug!("Writing share: {:?} to: {}", data, path.display());

        Ok(fs::write(path, data)?)
    }

    pub fn to_iso<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let mut cmd = Command::new("mkisofs");
        let output = cmd
            .arg("-r")
            .arg("-iso-level")
            .arg("4")
            .arg("-o")
            .arg(path.as_ref())
            .arg(self.tmp.as_ref())
            .output()
            .with_context(|| {
                format!(
                    "failed to create state ISO at \"{}\"",
                    self.tmp.as_ref().display()
                )
            })?;

        if !output.status.success() {
            warn!("command failed with status: {}", output.status);
            warn!("stderr: \"{}\"", String::from_utf8_lossy(&output.stderr));
            return Err(CdrwError::IsoFail.into());
        }

        Ok(())
    }

    /// Burn data to CD & eject disk when done.
    pub fn burn(self) -> Result<()> {
        use tempfile::NamedTempFile;

        let iso = NamedTempFile::new()?;
        self.to_iso(&iso)?;

        let mut cmd = Command::new("cdrecord");
        let output = cmd
            .arg("-eject")
            .arg("-data")
            .arg(iso.path())
            .arg(format!("dev={}", self.device.display()))
            .arg("gracetime=0")
            .arg("timeout=1000")
            .output()
            .with_context(|| {
                format!(
                    "failed to create ISO from \"{}\" at \"{}\"",
                    self.tmp.as_ref().display(),
                    self.tmp.as_ref().display()
                )
            })?;

        if !output.status.success() {
            warn!("command failed with status: {}", output.status);
            warn!("stderr: \"{}\"", String::from_utf8_lossy(&output.stderr));
            return Err(CdrwError::BurnFail.into());
        }

        Ok(())
    }

    /// Eject / open CD device.
    pub fn eject(&self) -> Result<()> {
        let mut cmd = Command::new("eject");
        let output = cmd.arg(&self.device).output().with_context(|| {
            format!("failed to eject CD device \"{}\"", self.device.display())
        })?;

        if !output.status.success() {
            warn!("command failed with status: {}", output.status);
            warn!("stderr: \"{}\"", String::from_utf8_lossy(&output.stderr));
            return Err(CdrwError::EjectFail.into());
        }

        Ok(())
    }
}

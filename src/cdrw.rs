// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{anyhow, Context, Result};
use log::{debug, warn};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use tempfile::{tempdir, TempDir};

pub struct IsoWriter {
    tmpdir: TempDir,
}

impl IsoWriter {
    pub fn new() -> Result<Self> {
        Ok(Self { tmpdir: tempdir()? })
    }

    pub fn add(&self, name: &str, data: &[u8]) -> Result<()> {
        let dst = self.tmpdir.path().join(name);

        fs::write(&dst, data).context(format!(
            "Failed to write data to: \"{}\"",
            dst.display()
        ))?;

        Ok(())
    }

    pub fn to_iso<P: AsRef<Path>>(self, path: P) -> Result<()> {
        let mut cmd = Command::new("mkisofs");
        let output = cmd
            .arg("-r")
            .arg("-iso-level")
            .arg("4")
            .arg("-o")
            .arg(path.as_ref())
            .arg(self.tmpdir.as_ref())
            .output()
            .with_context(|| {
                format!(
                    "failed to create ISO \"{}\" from dir \"{}\"",
                    path.as_ref().display(),
                    self.tmpdir.as_ref().display()
                )
            })?;

        if !output.status.success() {
            warn!("command failed with status: {}", output.status);
            warn!("stderr: \"{}\"", String::from_utf8_lossy(&output.stderr));
            return Err(anyhow!(format!(
                "Failed to make ISO {} from directory {}",
                path.as_ref().display(),
                self.tmpdir.as_ref().display()
            )));
        }

        Ok(())
    }
}

pub struct IsoReader {
    iso_file: PathBuf,
}

impl IsoReader {
    pub fn new<P: AsRef<Path>>(iso: P) -> Self {
        Self {
            iso_file: PathBuf::from(iso.as_ref()),
        }
    }

    pub fn read<P: AsRef<Path>>(&self, path: P) -> Result<Vec<u8>> {
        let loop_dev = loopback_setup(&self.iso_file)?;

        let tmpdir = tempdir()?;
        mount(&loop_dev, &tmpdir)?;

        let src = tmpdir.path().join(&path);
        let data = fs::read(src)?;

        unmount(&tmpdir)?;

        loopback_teardown(&loop_dev)?;

        Ok(data)
    }
}

// create loopback device for iso file and get the device path from
// losetup stdout
fn loopback_setup<P: AsRef<Path>>(iso_file: P) -> Result<String> {
    let mut cmd = Command::new("losetup");
    let output = cmd
        .arg("-f")
        .output()
        .with_context(|| "unable to execute \"losetup\"")?;

    debug!("executing command: \"{:#?}\"", cmd);

    if !output.status.success() {
        warn!("command failed with status: {}", output.status);
        warn!("stderr: \"{}\"", String::from_utf8_lossy(&output.stderr));
        return Err(anyhow!("Failed to get next available loopback device"));
    }

    let loop_dev = String::from(String::from_utf8(output.stdout)?.trim());
    debug!("got loopback device: {}", loop_dev);

    let mut cmd = Command::new("losetup");
    let output = cmd
        .arg(&loop_dev)
        .arg(iso_file.as_ref())
        .output()
        .with_context(|| "failed to execute \"losetup\"")?;

    debug!("executing command: \"{:#?}\"", cmd);
    if output.status.success() {
        Ok(loop_dev)
    } else {
        warn!("command failed with status: {}", output.status);
        warn!("stderr: \"{}\"", String::from_utf8_lossy(&output.stderr));
        Err(anyhow!(
            "Failed to create loopback device {} for ISO file {}",
            loop_dev,
            iso_file.as_ref().display()
        ))
    }
}

fn loopback_teardown<P: AsRef<Path>>(loop_dev: P) -> Result<()> {
    // tear down the loopback device
    let mut cmd = Command::new("losetup");
    let output = cmd
        .arg("-d")
        .arg(loop_dev.as_ref())
        .output()
        .context("failed to execute \"losetup\"")?;

    if output.status.success() {
        Ok(())
    } else {
        warn!("command failed with status: {}", output.status);
        warn!("stderr: \"{}\"", String::from_utf8_lossy(&output.stderr));
        Err(anyhow!(
            "Failed to delete loopback device {}",
            loop_dev.as_ref().display()
        ))
    }
}

// TODO: sys_mount crate
fn mount<P: AsRef<Path>, Q: AsRef<Path>>(
    device: P,
    mount_point: Q,
) -> Result<()> {
    let mut cmd = Command::new("mount");
    let output = cmd
        .arg(device.as_ref())
        .arg(mount_point.as_ref())
        .output()
        .with_context(|| {
            format!(
                "failed to mount \"{}\" at \"{}\"",
                device.as_ref().display(),
                mount_point.as_ref().display()
            )
        })?;

    if output.status.success() {
        Ok(())
    } else {
        warn!("command failed with status: {}", output.status);
        warn!("stderr: \"{}\"", String::from_utf8_lossy(&output.stderr));
        Err(anyhow!(
            "Failed to mount device {} at {}",
            device.as_ref().display(),
            mount_point.as_ref().display()
        ))
    }
}

fn unmount<P: AsRef<Path>>(mount_point: P) -> Result<()> {
    // unmount now that we've got the data we need
    let mut cmd = Command::new("umount");
    let output = cmd.arg(mount_point.as_ref()).output().with_context(|| {
        format!("failed to unmount \"{}\"", mount_point.as_ref().display())
    })?;

    if output.status.success() {
        Ok(())
    } else {
        warn!("command failed with status: {}", output.status);
        warn!("stderr: \"{}\"", String::from_utf8_lossy(&output.stderr));
        Err(anyhow!(
            "Failed to unmount at {}",
            mount_point.as_ref().display()
        ))
    }
}

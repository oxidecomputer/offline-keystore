// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{anyhow, Context, Result};
use log::{debug, warn};
use std::{
    fs,
    ops::Deref,
    os::unix::fs::FileTypeExt,
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::Duration,
};
use tempfile::{tempdir, TempDir};
use zeroize::Zeroizing;

use crate::backup::Share;

pub static CD_DEVS: &[&str] = &["/dev/cdrom", "/dev/sr0"];
static RETRY_COUNT: u32 = 5;
static RETRY_SLEEP: u64 = 2;

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
        let cmd = cmd
            .arg("-r")
            .arg("-iso-level")
            .arg("4")
            .arg("-o")
            .arg(path.as_ref())
            .arg(self.tmpdir.as_ref());

        debug!("executing command: {:?}", cmd);
        let output = cmd
            .output()
            .context("failed to execute mkisofs, check PATH")?;

        if output.status.success() {
            Ok(())
        } else {
            warn!(
                "mkisofs failed with status: {}, stderr: \"{}\"",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
            Err(anyhow!(format!(
                "Failed to make ISO {} from directory {}",
                path.as_ref().display(),
                self.tmpdir.as_ref().display()
            )))
        }
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

        // we're mounting a loopback device, no need to wait for it
        mount(&loop_dev, &tmpdir)?;

        let src = tmpdir.path().join(&path);
        let data = fs::read(src)?;

        unmount(&tmpdir)?;

        loopback_teardown(&loop_dev)?;

        Ok(data)
    }
}

fn find_cd_dev() -> Option<PathBuf> {
    let mut devices = CD_DEVS.iter().filter(|d| match fs::metadata(d) {
        Err(_) => false,
        Ok(m) => m.file_type().is_block_device(),
    });

    devices.next().map(PathBuf::from)
}

pub struct CdReader {
    device: PathBuf,
}

impl CdReader {
    pub fn new<P: AsRef<Path>>(device: Option<P>) -> Result<Self> {
        let device = match device {
            Some(s) => PathBuf::from(s.as_ref()),
            None => match find_cd_dev() {
                None => {
                    return Err(anyhow::anyhow!("unable to find CD device"))
                }
                Some(p) => p,
            },
        };
        Ok(Self { device })
    }

    pub fn eject(&self) -> Result<()> {
        eject(&self.device)
    }

    pub fn read(&self, name: &str) -> Result<Vec<u8>> {
        let tmpdir = tempdir()?;

        wait_for_media(&self.device)?;
        mount(&self.device, &tmpdir)?;

        let path = tmpdir.as_ref().join(name);
        debug!("reading data from {}", path.display());

        let res = fs::read(&path).with_context(|| {
            format!("failed to read file: {} from Cdr", path.display())
        });
        unmount(&tmpdir)?;

        res
    }
}

pub struct CdWriter {
    iso_writer: IsoWriter,
    device: PathBuf,
}

impl CdWriter {
    pub fn new<P: AsRef<Path>>(device: Option<P>) -> Result<Self> {
        let device = match device {
            Some(s) => PathBuf::from(s.as_ref()),
            None => match find_cd_dev() {
                None => {
                    return Err(anyhow::anyhow!("unable to find CD device"))
                }
                Some(p) => p,
            },
        };

        Ok(Self {
            device,
            iso_writer: IsoWriter::new()?,
        })
    }

    pub fn write_password(&self, data: &Zeroizing<String>) -> Result<()> {
        debug!(
            "Writing password \"{}\"",
            <Zeroizing<String> as AsRef<str>>::as_ref(data),
        );
        self.iso_writer.add("password", data.deref().as_bytes())
    }

    pub fn write_share(&self, data: &Zeroizing<Share>) -> Result<()> {
        debug!("Writing share: {:?}", data.deref());
        self.iso_writer.add("share", data.deref().as_ref())
    }

    /// Burn data to CD & eject disk when done.
    pub fn burn(self) -> Result<()> {
        use tempfile::NamedTempFile;

        let iso = NamedTempFile::new()?;
        self.iso_writer.to_iso(&iso)?;

        wait_for_media(&self.device)?;

        let mut cmd = Command::new("cdrecord");
        let cmd = cmd
            .arg("-eject")
            .arg("-data")
            .arg(iso.path())
            .arg(format!("dev={}", self.device.display()))
            .arg("gracetime=0")
            .arg("timeout=1000");

        debug!("executing command: {:?}", cmd);
        let output = cmd
            .output()
            .context("failed to execute cdrecord, check PATH")?;

        if output.status.success() {
            Ok(())
        } else {
            warn!(
                "cdrecord failed with status: {}, stderr: \"{}\"",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
            Err(anyhow!(
                "Failed to burn ISO {} to device {}",
                iso.path().display(),
                self.device.display()
            ))
        }
    }

    /// Eject / open CD device.
    pub fn eject(&self) -> Result<()> {
        eject(&self.device)
    }
}

// create loopback device for iso file and get the device path from
// losetup stdout
fn loopback_setup<P: AsRef<Path>>(iso_file: P) -> Result<String> {
    let mut cmd = Command::new("losetup");
    let cmd = cmd.arg("-f");

    debug!("executing command: {:?}", cmd);
    let output = cmd
        .output()
        .context("failed to execute losetup, check PATH")?;

    if !output.status.success() {
        warn!(
            "losetup failed with status: {}, stderr: \"{}\"",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        return Err(anyhow!("Failed to get next available loopback device"));
    }

    let loop_dev = String::from(String::from_utf8(output.stdout)?.trim());
    debug!("got loopback device: {}", loop_dev);

    let mut cmd = Command::new("losetup");
    let cmd = cmd.arg(&loop_dev).arg(iso_file.as_ref());

    debug!("executing command: {:?}", cmd);
    let output = cmd
        .output()
        .context("failed to execute losetup, check PATH")?;

    if output.status.success() {
        Ok(loop_dev)
    } else {
        warn!(
            "losetup failed with status: {}, stderr: \"{}\"",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
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
    let cmd = cmd.arg("-d").arg(loop_dev.as_ref());

    debug!("executing command: {:?}", cmd);
    let output = cmd
        .output()
        .context("failed to execute losetup, check PATH")?;

    if output.status.success() {
        Ok(())
    } else {
        warn!(
            "losetup failed with status: {}, stderr: \"{}\"",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
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
    let cmd = cmd.arg(device.as_ref()).arg(mount_point.as_ref());

    debug!("execting command: {:?}", cmd);
    let output = cmd.output().with_context(|| {
        format!(
            "failed to execute mount command \"{}\" at \"{}\"",
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
    let cmd = cmd.arg(mount_point.as_ref());

    debug!("execting command: {:?}", cmd);
    let output = cmd.output().with_context(|| {
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

pub fn eject<P: AsRef<Path>>(device: P) -> Result<()> {
    let mut cmd = Command::new("eject");
    let output = cmd.arg(device.as_ref()).output().with_context(|| {
        format!("failed to run the \"eject\" command: \"{:?}\"", cmd)
    })?;

    debug!("execting command: {:?}", cmd);
    if output.status.success() {
        Ok(())
    } else {
        warn!("command failed with status: {}", output.status);
        warn!("stderr: \"{}\"", String::from_utf8_lossy(&output.stderr));
        Err(anyhow!(
            "Failed to eject optical device \"{}\"",
            device.as_ref().display()
        ))
    }
}

fn wait_for_media<P: AsRef<Path>>(device: P) -> Result<()> {
    let mut cmd = Command::new("blockdev");
    let cmd = cmd.arg("--getsize64").arg(device.as_ref());

    let mut count = 0;
    let mut sleep = RETRY_SLEEP;
    loop {
        debug!("execting command: {:?}", cmd);
        let output = cmd
            .output()
            .context("faild to execute blockdev, check PATH")?;

        if output.status.success() {
            debug!("disk detected in drive, continuing");
            break Ok(());
        } else {
            count += 1;
            sleep += sleep;
            if count < RETRY_COUNT {
                debug!(
                    "no medium in drive {} after {} attempts, retrying in \
                    {} seconds",
                    device.as_ref().display(),
                    count,
                    sleep
                );
                thread::sleep(Duration::from_secs(sleep));
                continue;
            } else {
                break Err(anyhow!(
                    "No medium found in drive {} after {} retries, failing",
                    device.as_ref().display(),
                    RETRY_COUNT,
                ));
            }
        }
    }
}

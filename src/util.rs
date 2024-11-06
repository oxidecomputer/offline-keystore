// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{Context, Result};

/// This function is used when displaying key shares as a way for the user to
/// control progression through the key shares displayed in the terminal.
pub fn wait_for_line() -> Result<()> {
    let _ = std::io::stdin()
        .lines()
        .next()
        .unwrap()
        .context("Failed to get a line from from Stdin")?;

    Ok(())
}

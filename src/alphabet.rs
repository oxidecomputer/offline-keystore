// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{Context, Result};
use rand_core::RngCore;
use std::collections::HashSet;

pub struct Alphabet {
    chars: Vec<char>,
}

impl Default for Alphabet {
    fn default() -> Self {
        Self::new()
    }
}

impl Alphabet {
    pub fn new() -> Self {
        let mut chars: HashSet<char> = HashSet::new();
        chars.extend('a'..='z');
        chars.extend('A'..='Z');
        chars.extend('0'..='9');

        // Remove visually similar characters
        chars = &chars - &HashSet::from(['l', 'I', '1']);
        chars = &chars - &HashSet::from(['B', '8']);
        chars = &chars - &HashSet::from(['O', '0']);

        // We generate random passwords from this alphabet by getting a byte
        // of random data from the HSM and using this value to pick
        // characters from the alphabet. Our alphabet cannot be larger than
        // the u8::MAX or it will ignore characters after the u8::MAXth.
        assert!(usize::from(u8::MAX) > chars.len());

        Alphabet {
            chars: chars.into_iter().collect(),
        }
    }

    pub fn get_char(&self, val: u8) -> Option<char> {
        let len = self.chars.len() as u8;
        // let rand = ;
        // Avoid biasing results by ensuring the random values we use
        // are a multiple of the length of the alphabet. If they aren't
        // we just get another.
        if val < u8::MAX - u8::MAX % len {
            Some(self.chars[(val % len) as usize])
        } else {
            None
        }
    }

    pub fn get_random_string<R: RngCore>(
        &self,
        rng: &mut R,
        length: usize,
    ) -> Result<String> {
        let mut passwd = String::with_capacity(length + 1);
        let mut byte = [0u8, 1];

        for i in 0..length {
            let char = loop {
                rng.try_fill_bytes(&mut byte).with_context(|| {
                    format!("failed to get byte {} for password", i)
                })?;

                if let Some(char) = self.get_char(byte[0]) {
                    break char;
                }
            };

            passwd.push(char);
        }

        Ok(passwd)
    }
}

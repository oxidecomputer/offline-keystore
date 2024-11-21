// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use log::{debug, info};
use p256::{
    elliptic_curve::PrimeField, NonZeroScalar, ProjectivePoint, Scalar,
    SecretKey,
};
use rand_core::{CryptoRng, RngCore};
use std::ops::Deref;
use vsss_rs::{Feldman, FeldmanVerifier};
use zeroize::{DefaultIsZeroes, Zeroizing};

pub const KEY_LEN: usize = 32;
const SHARE_LEN: usize = KEY_LEN + 1;

pub const LIMIT: usize = 5;
pub const THRESHOLD: usize = 3;
static_assertions::const_assert!(THRESHOLD <= LIMIT);

pub type Share = vsss_rs::Share<SHARE_LEN>;
pub type SharesMax = [Share; LIMIT];
pub type Verifier = FeldmanVerifier<Scalar, ProjectivePoint, THRESHOLD>;

/// A key we use to backup keys in the HSM. This type implements operations we
/// perform on / with this key when it's not in the HSM.
#[derive(Clone, Copy, Default)]
pub struct BackupKey([u8; KEY_LEN]);

impl DefaultIsZeroes for BackupKey {}

impl BackupKey {
    pub fn from_rng<T: RngCore>(rng: &mut T) -> Result<Self> {
        let mut key = [0u8; KEY_LEN];
        rng.try_fill_bytes(&mut key)?;
        Ok(Self(key))
    }

    // use as_bytes::AsBytes;
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    // impl From<SharesThreshold> for BackupKey {} or something?
    pub fn from_shares(shares: Zeroizing<Vec<Share>>) -> Result<Self> {
        let scalar = Feldman::<THRESHOLD, LIMIT>::combine_shares::<
            Scalar,
            SHARE_LEN,
        >(shares.deref())
        .map_err(|e| {
            anyhow::anyhow!(format!("Failed to combine_shares: {}", e))
        })?;

        let nz_scalar = NonZeroScalar::from_repr(scalar.to_repr());
        let nz_scalar = if nz_scalar.is_some().into() {
            nz_scalar.unwrap()
        } else {
            return Err(anyhow::anyhow!(
                "Failed to construct NonZeroScalar from Scalar"
            ));
        };

        // not sure this is necessary ... can we just get it from the Scalar?
        let wrap_key = SecretKey::from(nz_scalar);

        //let foo: [u8; KEY_LEN] = wrap_key.to_be_bytes().try_into()?;

        Ok(Self(wrap_key.to_be_bytes().into()))
    }

    pub fn split<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
    ) -> Result<(Zeroizing<SharesMax>, Verifier)> {
        info!("Splitting wrap key into {} shares.", LIMIT);
        let wrap_key =
            SecretKey::from_be_bytes(self.as_bytes()).map_err(|e| {
                anyhow::anyhow!("Failed to construct SecretKey: {}", e)
            })?;
        debug!("wrap key: {:?}", wrap_key.to_be_bytes());

        let nzs = wrap_key.to_nonzero_scalar();
        let (shares, verifier) = Feldman::<THRESHOLD, LIMIT>::split_secret::<
            Scalar,
            ProjectivePoint,
            R,
            SHARE_LEN,
        >(*nzs.as_ref(), None, &mut *rng)
        .map_err(|e| anyhow::anyhow!("Failed to split_secret: {}", e))?;

        Ok((Zeroizing::new(shares), verifier))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;

    // secret split into the feldman verifier & shares below
    const SECRET: &str =
        "f259a45c17624b9317d8e292050c46a0f3d7387724b4cd26dd94f8bd3d1c0e1a";

    // verifier created and serialized to json by `new_split_wrap`
    const VERIFIER: &str = r#"
    {
        "generator": "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "commitments": [
            "022f65c477affe7de97a51b8e562e763030218a8f0a8ecd7c349a50df7ded44985",
            "03365076080ebeeab74e2421fa0f4e4c5796ad3cbd157cc0405b100a45ae89f22f",
            "02bbd29359d702ff89ab2cbdb9e6ae102dfb1c4108aeab0701a469f28f0ad1e813"
        ]
    }"#;

    // shares dumped to the printer by `new_split_wrap`
    const SHARE_ARRAY: [&str; LIMIT] = [
        "01a69b62eb1a7c9deb5435ca73bf6f5e280279ba9cbdcd873d4decb665fb8aaf34",
        "020495513aa59e274196125218ff57b2f01f6bf97d817d24a1a00c5fbf29af08a8",
        "030c476f49b8c6e796dd6e7981c4c544f90794efc716db43d8c7adbf8bc3ec3fc7",
        "04bdb1bd1853f6deeb2a4a40ae0fb81442baf49d797de7e4e2c4d0d5cbca425491",
        "0518d43aa8772e0d3c7ca5a79de03020cdbfbd0d396873cab5b0020cf943eafc64",
    ];

    fn secret_bytes() -> [u8; KEY_LEN] {
        let mut secret = [0u8; KEY_LEN];
        hex::decode_to_slice(SECRET, &mut secret).unwrap();

        secret
    }

    fn deserialize_share(share: &str) -> Result<Share> {
        // filter out whitespace to keep hex::decode happy
        let share: String =
            share.chars().filter(|c| !c.is_whitespace()).collect();
        let share = hex::decode(share)
            .context("failed to decode share from hex string")?;

        Ok(Share::try_from(&share[..])
            .context("Failed to construct Share from bytes.")?)
    }

    #[test]
    fn round_trip() -> Result<()> {
        use rand::rngs::ThreadRng;

        let secret = secret_bytes();
        let secret_key = SecretKey::from_be_bytes(&secret)?;
        let nzs = secret_key.to_nonzero_scalar();

        let mut rng = ThreadRng::default();
        let (shares, verifier) = Feldman::<THRESHOLD, LIMIT>::split_secret::<
            Scalar,
            ProjectivePoint,
            ThreadRng,
            SHARE_LEN,
        >(*nzs.as_ref(), None, &mut rng)
        .map_err(|e| anyhow::anyhow!("failed to split secret: {}", e))?;

        for s in &shares {
            assert!(verifier.verify(s));
        }

        let scalar = Feldman::<THRESHOLD, LIMIT>::combine_shares::<
            Scalar,
            SHARE_LEN,
        >(&shares)
        .map_err(|e| anyhow::anyhow!("failed to combine secret: {}", e))?;

        let nzs_dup = NonZeroScalar::from_repr(scalar.to_repr()).unwrap();
        let sk_dup = SecretKey::from(nzs_dup);
        let new_secret: [u8; KEY_LEN] = sk_dup.to_be_bytes().try_into()?;

        assert_eq!(new_secret, secret);

        Ok(())
    }

    // deserialize a verifier & use it to verify the shares in SHARE_ARRAY
    #[test]
    fn verify_shares() -> Result<()> {
        let verifier: Verifier = serde_json::from_str(VERIFIER)
            .context("Failed to deserialize Verifier from JSON.")?;

        for share in SHARE_ARRAY {
            let share = deserialize_share(share)?;
            assert!(verifier.verify(&share));
        }

        Ok(())
    }

    #[test]
    fn verify_zero_share() -> Result<()> {
        let verifier: Verifier = serde_json::from_str(VERIFIER)
            .context("Failed to deserialize FeldmanVerifier from JSON.")?;

        let share = Share::try_from([0u8; SHARE_LEN].as_ref())
            .context("Failed to create Share from static array.")?;

        assert!(!verifier.verify(&share));

        Ok(())
    }

    // TODO: I had expected that changing a single bit in a share would case
    // the verifier to fail but that seems to be very wrong.
    #[test]
    fn verify_share_with_changed_byte() -> Result<()> {
        let verifier: Verifier = serde_json::from_str(VERIFIER)
            .context("Failed to deserialize FeldmanVerifier from JSON.")?;

        let mut share = deserialize_share(SHARE_ARRAY[0])?;
        println!("share: {}", share.0[0]);
        share.0[1] = 0xff;
        share.0[2] = 0xff;
        share.0[3] = 0xff;
        // If we don't change the next byte this test will start failing.
        // I had (wrongly?) expected that the share would fail to verify w/
        // a single changed byte
        share.0[4] = 0xff;

        assert!(!verifier.verify(&share));

        Ok(())
    }

    #[test]
    fn recover_secret() -> Result<()> {
        let mut shares: Vec<Share> = Vec::new();
        for share in SHARE_ARRAY {
            shares.push(deserialize_share(share)?);
        }

        let scalar = Feldman::<THRESHOLD, LIMIT>::combine_shares::<
            Scalar,
            SHARE_LEN,
        >(&shares)
        .map_err(|e| anyhow::anyhow!("failed to combine secret: {}", e))?;

        let nzs_dup = NonZeroScalar::from_repr(scalar.to_repr()).unwrap();
        let sk_dup = SecretKey::from(nzs_dup);
        let secret: [u8; KEY_LEN] = sk_dup.to_be_bytes().try_into()?;

        assert_eq!(secret, secret_bytes());

        Ok(())
    }

    #[test]
    fn from_rng() -> Result<()> {
        let mut rng = rand::thread_rng();
        let backup_key = BackupKey::from_rng(&mut rng);

        assert!(backup_key.is_ok());

        Ok(())
    }
}

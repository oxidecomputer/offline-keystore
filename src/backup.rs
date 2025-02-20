// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{anyhow, Context, Result};
use log::{debug, info};
use p256::{
    elliptic_curve::{generic_array::typenum::Unsigned, Curve, PrimeField},
    NistP256, NonZeroScalar, ProjectivePoint, Scalar, SecretKey,
};
use rand_core::{CryptoRng, RngCore};
use std::ops::Deref;
use vsss_rs::{
    feldman, DefaultShare, FeldmanVerifierSet, IdentifierPrimeField,
    ReadableShareSet, ShareVerifierGroup,
};

use zeroize::{DefaultIsZeroes, Zeroizing};

// I think I prefer having this be a simple: `let KEY_LEN: usize = 32;`
pub const KEY_LEN: usize = <NistP256 as Curve>::FieldBytesSize::USIZE;

pub const LIMIT: usize = 5;
pub const THRESHOLD: usize = 3;
static_assertions::const_assert!(THRESHOLD <= LIMIT);

pub type Share =
    DefaultShare<IdentifierPrimeField<Scalar>, IdentifierPrimeField<Scalar>>;
pub type Verifier = ShareVerifierGroup<ProjectivePoint>;

// TODO: these should be member functions / From ... on a local share type?
pub fn share_from_hex(share: &str) -> Result<Zeroizing<Share>> {
    // we get the `with_identifier_and_value` constructor for the DefaultShare
    // type from the `vsss_rs::Share` trait
    use vsss_rs::Share as vShare;

    let share: String = share.chars().filter(|c| !c.is_whitespace()).collect();
    let share = hex::decode(share)
        .context("The provided string includs non-hex characters")?;

    // extract the share identifier and build up the type to hold it
    // In the hex representation (what we printed out) the first byte from
    // the string is the share identifier. In the serialized scalar
    // representation (repr) it's the last byte.
    let mut id: [u8; KEY_LEN] = [0; KEY_LEN];
    id[id.len() - 1] = share[0];
    let id = id;
    let id = Scalar::from_repr(id.into())
        .into_option()
        .ok_or(anyhow!("Failed create scalar from identifier byte repr"))?;
    let id = IdentifierPrimeField::from(id);

    // extract the share value and build up the type to hold it
    let value: [u8; KEY_LEN] = share[1..]
        .try_into()
        .context("Converting share bytes to value array")?;
    let value = Scalar::from_repr(value.into())
        .into_option()
        .ok_or(anyhow!("Failed create scalar from value byte repr"))?;
    let value = IdentifierPrimeField::from(value);

    let share = Share::with_identifier_and_value(id, value);

    // combine the identifier and the value into the Share
    Ok(Zeroizing::new(share))
}

pub fn share_to_hex(share: &Zeroizing<Share>) -> Result<String> {
    // KEY_LEN + 1: the number of bytes in a key share that's been serialized
    // to hex. This is the key length w/ an extra byte for the share index.
    let mut bytes = [0u8; KEY_LEN + 1];

    // the first byte / LSB of the identifier is the index
    // this becomes the MSB of the serialized representation
    // TODO: error if identifier > 0xff
    bytes[0] = *share
        .deref()
        .identifier
        .as_ref()
        .to_bytes()
        .last()
        .ok_or(anyhow!("Empty share identifier slice"))?;

    bytes[1..].copy_from_slice(&share.deref().value.as_ref().to_bytes());
    Ok(hex::encode(bytes))
}

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
        let secret = shares.deref().combine().map_err(|e| {
            anyhow::anyhow!(format!("Failed to combine shares: {}", e))
        })?;

        let nz_scalar = NonZeroScalar::new(*secret.as_ref());
        let nz_scalar = if nz_scalar.is_some().into() {
            nz_scalar.unwrap()
        } else {
            return Err(anyhow::anyhow!(
                "Failed to construct NonZeroScalar from Scalar"
            ));
        };

        // not sure this is necessary ... can we just get it from the Scalar?
        let wrap_key = SecretKey::from(&nz_scalar);

        //let foo: [u8; KEY_LEN] = wrap_key.to_be_bytes().try_into()?;

        Ok(Self(wrap_key.to_bytes().into()))
    }

    pub fn split<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
    ) -> Result<(Zeroizing<Vec<Share>>, Vec<Verifier>)> {
        // turn our 32 byte secret into a p256 key
        info!("Splitting wrap key into {} shares.", LIMIT);
        let wrap_key = SecretKey::from_slice(self.as_bytes()).map_err(|e| {
            anyhow::anyhow!("Failed to construct SecretKey: {}", e)
        })?;
        debug!("wrap key: {:?}", wrap_key.to_bytes());

        // massage it into the right type before splitting it up
        let nzs = wrap_key.to_nonzero_scalar();
        let secret = IdentifierPrimeField(*nzs.as_ref());
        let (shares, verifier) = feldman::split_secret::<Share, Verifier>(
            THRESHOLD, LIMIT, &secret, None, rng,
        )
        .map_err(|e| anyhow::anyhow!("Failed to split_secret: {}", e))?;

        // verify shares before returning them
        for (i, s) in shares.iter().enumerate() {
            verifier.verify_share(s).map_err(|e| {
                anyhow!("Share {} failed to verification: {}", i, e)
            })?;
        }

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

    // `Vec<Verifier>` created and serialized to json
    const VERIFIER: &str = r#"
    [
        "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "022f65c477affe7de97a51b8e562e763030218a8f0a8ecd7c349a50df7ded44985",
        "03365076080ebeeab74e2421fa0f4e4c5796ad3cbd157cc0405b100a45ae89f22f",
        "02bbd29359d702ff89ab2cbdb9e6ae102dfb1c4108aeab0701a469f28f0ad1e813"
    ]"#;

    // formatted for vsss_rs > 5.x
    const SHARE_0: &str = r#"
    {
        "identifier":"0000000000000000000000000000000000000000000000000000000000000001",
        "value":"a69b62eb1a7c9deb5435ca73bf6f5e280279ba9cbdcd873d4decb665fb8aaf34"
    }"#;
    // formatted for vsss_rs ~2.x
    // we maintain compatibility w/ this format to support key shares that have
    // already been distributed
    const SHARE_0_HEX: &str =
        "01a69b62eb1a7c9deb5435ca73bf6f5e280279ba9cbdcd873d4decb665fb8aaf34";

    const SHARE_1: &str = r#"
    {
        "identifier":"0000000000000000000000000000000000000000000000000000000000000002",
        "value":"0495513aa59e274196125218ff57b2f01f6bf97d817d24a1a00c5fbf29af08a8"
    }"#;
    const SHARE_1_HEX: &str =
        "020495513aa59e274196125218ff57b2f01f6bf97d817d24a1a00c5fbf29af08a8";

    const SHARE_2: &str = r#"
    {
        "identifier":"0000000000000000000000000000000000000000000000000000000000000003",
        "value":"0c476f49b8c6e796dd6e7981c4c544f90794efc716db43d8c7adbf8bc3ec3fc7"
    }"#;
    const SHARE_2_HEX: &str =
        "030c476f49b8c6e796dd6e7981c4c544f90794efc716db43d8c7adbf8bc3ec3fc7";

    const SHARE_3: &str = r#"
    {
        "identifier":"0000000000000000000000000000000000000000000000000000000000000004",
        "value":"bdb1bd1853f6deeb2a4a40ae0fb81442baf49d797de7e4e2c4d0d5cbca425491"
    }"#;
    const SHARE_3_HEX: &str =
        "04bdb1bd1853f6deeb2a4a40ae0fb81442baf49d797de7e4e2c4d0d5cbca425491";

    const SHARE_4: &str = r#"
    {
        "identifier":"0000000000000000000000000000000000000000000000000000000000000005",
        "value":"18d43aa8772e0d3c7ca5a79de03020cdbfbd0d396873cab5b0020cf943eafc64"
    }"#;
    const SHARE_4_HEX: &str =
        "0518d43aa8772e0d3c7ca5a79de03020cdbfbd0d396873cab5b0020cf943eafc64";

    const SHARE_ARRAY: [&str; LIMIT] =
        [SHARE_0, SHARE_1, SHARE_2, SHARE_3, SHARE_4];
    const SHARE_ARRAY_HEX: [&str; LIMIT] = [
        SHARE_0_HEX,
        SHARE_1_HEX,
        SHARE_2_HEX,
        SHARE_3_HEX,
        SHARE_4_HEX,
    ];

    fn secret_bytes() -> [u8; KEY_LEN] {
        let mut secret = [0u8; KEY_LEN];
        hex::decode_to_slice(SECRET, &mut secret).unwrap();

        secret
    }

    #[test]
    fn round_trip() -> Result<()> {
        use rand::rngs::ThreadRng;

        let secret = secret_bytes();
        let secret = Scalar::from_repr(secret.try_into()?)
            .into_option()
            .ok_or(anyhow!("Create Scalar from bytes"))?;
        let secret = NonZeroScalar::new(secret)
            .into_option()
            .ok_or(anyhow!("Create NonZeroScalar from Scalar"))?;
        let secret_key = SecretKey::from(secret);
        let nzs = secret_key.to_nonzero_scalar();
        let secret = IdentifierPrimeField(*nzs.as_ref());

        let mut rng = ThreadRng::default();
        let (shares, verifier) = feldman::split_secret::<Share, Verifier>(
            THRESHOLD, LIMIT, &secret, None, &mut rng,
        )
        .map_err(|e| anyhow::anyhow!("failed to split secret: {}", e))?;

        for s in &shares {
            assert!(verifier.verify_share(s).is_ok());
        }

        let secret_1 = shares
            .combine()
            .map_err(|e| anyhow::anyhow!("failed to combine secret: {}", e))?;

        assert_eq!(secret_1, secret);

        Ok(())
    }

    // deserialize the verifier & use it to verify all shares deserialized from
    // the hex representation
    #[test]
    fn verify_shares_hex() -> Result<()> {
        let verifier: Vec<Verifier> = serde_json::from_str(VERIFIER)
            .context("Failed to deserialize Verifier from JSON.")?;

        for share in SHARE_ARRAY_HEX {
            let share = share_from_hex(share)?;
            assert!(verifier.verify_share(share.deref()).is_ok());
        }

        Ok(())
    }

    // deserialize the verifier & use it to verify all shares deserialized
    // from the JSON representation
    #[test]
    fn verify_shares() -> Result<()> {
        let verifier: Vec<Verifier> = serde_json::from_str(VERIFIER)
            .context("Failed to deserialize Verifier from JSON.")?;

        for (i, share) in SHARE_ARRAY.iter().enumerate() {
            let share: Share = serde_json::from_str(&share)
                .context(format!("Share {} from json", i))?;
            assert!(verifier.verify_share(&share).is_ok());
        }

        Ok(())
    }

    #[test]
    fn verify_share_with_changed_byte() -> Result<()> {
        // modifying the share deserialized from hex is a lot more work
        let share: String = SHARE_ARRAY_HEX[0]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        let mut share = hex::decode(share)?;

        // change a single byte in a known good share
        share[4] = 0xff;
        let share = share;
        let share = hex::encode(&share);

        // modifying the share seems to make an invalid scalar
        let share = share_from_hex(&share)?;

        let verifier: Vec<Verifier> = serde_json::from_str(VERIFIER)
            .context("Failed to deserialize FeldmanVerifier from JSON.")?;

        assert!(!verifier.verify_share(share.deref()).is_ok());

        Ok(())
    }

    #[test]
    fn recover_secret() -> Result<()> {
        let mut shares: Vec<Share> = Vec::new();
        for share in SHARE_ARRAY_HEX {
            shares.push(*share_from_hex(share)?);
        }
        let shares = shares;

        let scalar = shares
            .combine()
            .map_err(|e| anyhow!("Failed to combine shares: {}", e))?;

        let nzs_dup = NonZeroScalar::from_repr(scalar.to_repr()).unwrap();
        let sk_dup = SecretKey::from(nzs_dup);
        let secret: [u8; KEY_LEN] = sk_dup.to_bytes().try_into()?;

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

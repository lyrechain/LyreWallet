use crate::{global::StorageCipher, DangerousDebugPrint, LyreChainError, LyreWalletOps, Result};
use arrayvec::ArrayVec;
use async_fs::OpenOptions;
use borsh::{BorshDeserialize, BorshSerialize};
use camino::Utf8Path;
use ed25519_dalek::Keypair;
use futures_lite::{prelude::*, AsyncReadExt, AsyncWriteExt};
use rand::rngs::OsRng;
use secrecy::{ExposeSecret, Secret};
use std::convert::TryInto;

pub struct LyreKeyPair {
    privkey: Secret<[u8; 32]>,
    pub pubkey: ArrayVec<u8, 32>,
}

impl LyreKeyPair {
    pub fn new_key(&mut self) -> &mut Self {
        let mut csprng = OsRng {};
        let keypair: Keypair = Keypair::generate(&mut csprng);

        self.privkey = Secret::new(keypair.secret.to_bytes());
        self.pubkey[..].copy_from_slice(&keypair.public.to_bytes());

        self
    }

    pub fn get_pubkey(&self) -> ArrayVec<u8, 32> {
        self.pubkey.clone()
    }

    /// Warning!!! This clones the current private key
    pub fn get_privkey(&self) -> Secret<[u8; 32]> {
        Secret::new(self.privkey.expose_secret().clone())
    }

    /// Dangerous op; Stores keypairs as plain text
    /// Useful for debuging only
    pub async fn save_dangerously(
        &self,
        path: &Utf8Path,
    ) -> futures_lite::io::Result<LyreWalletOps> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .await?;

        let mut buffer = [0_u8; 65];

        buffer[0] = 0x00;
        buffer[1..=32].copy_from_slice(self.privkey.expose_secret());
        buffer[33..=64].copy_from_slice(&self.pubkey);

        file.write_all(&buffer).await?;
        file.flush().await?;

        Ok(LyreWalletOps::KeySavedToDangerousStorage)
    }

    pub async fn load_fs(&mut self, path: &Utf8Path) -> Result<LyreWalletOps> {
        let mut file = OpenOptions::new()
            .write(false)
            .read(true)
            .open(path)
            .await?;

        let mut buffer = [0_u8; 65];

        file.read(&mut buffer[..]).await?;

        let cipher = match buffer[0] {
            0x00 => StorageCipher::PlainBytes,
            0x01 => StorageCipher::Base58,
            0x02 => StorageCipher::XChaCha20Blake3Aead,
            0x03 => StorageCipher::XChaCha12Blake3Aead,
            0x04 => StorageCipher::XChaCha8Blake3Aead,
            _ => StorageCipher::UnsupportedCipher,
        };

        match cipher {
            StorageCipher::PlainBytes => {
                let privkey: [u8; 32] = match buffer[1..=32].try_into() {
                    Ok(value) => value,
                    Err(_) => return Err(LyreChainError::TryIntoU8_32LenError),
                };

                let pubkey: [u8; 32] = match buffer[33..=64].try_into() {
                    Ok(value) => value,
                    Err(_) => return Err(LyreChainError::TryIntoU8_32LenError),
                };

                self.privkey = Secret::new(privkey);
                self.pubkey = ArrayVec::from(pubkey);
            }
            _ => {
                dbg!("unreachable!()");
            } //TODO
        }

        Ok(LyreWalletOps::LoadedKeyPair)
    }
}

impl core::fmt::Debug for LyreKeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LyreKeyPair")
            .field("privkey", &"REDACTED")
            .field("PUB_KEY", &self.pubkey)
            .finish()
    }
}

impl core::fmt::Display for LyreKeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LyreKeyPair")
            .field("privkey", &"REDACTED")
            .field("PUB_KEY", &self.pubkey)
            .finish()
    }
}

impl DangerousDebugPrint for LyreKeyPair {
    fn dangerous_debug(&self) {
        println!(
            "LyreKeyPair {{ privkey: {:?}, pubkey: {:?} }}",
            self.privkey.expose_secret(),
            self.pubkey
        );
    }
}

impl Default for LyreKeyPair {
    fn default() -> Self {
        Self {
            privkey: Secret::new([0_u8; 32]),
            pubkey: ArrayVec::from([0_u8; 32]),
        }
    }
}

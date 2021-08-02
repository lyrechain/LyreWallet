use crate::{DangerousDebugPrint};
use arrayvec::ArrayVec;
use ed25519_dalek::Keypair;
use rand::rngs::OsRng;
use secrecy::{ExposeSecret, Secret};

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
}

impl core::fmt::Debug for LyreKeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LyreKeyPair")
            .field("privkey", &"R3DACT3D")
            .field("PUB_KEY", &self.pubkey)
            .finish()
    }
}

impl core::fmt::Display for LyreKeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LyreKeyPair")
            .field("privkey", &"R3DACT3D")
            .field("PUB_KEY", &self.pubkey)
            .finish()
    }
}

impl DangerousDebugPrint for LyreKeyPair {
    fn dangerous_debug(&self) {
        println!(
            "LyreKeyPair {{ privkey: {:?}, pubkey: {:?} }}",
            self.privkey, self.pubkey
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

use crate::{DangerousDebugPrint, LyreOpsOutcome};
use arrayvec::ArrayVec;
use ed25519_dalek::Keypair;
use rand::rngs::OsRng;
use zeroize::Zeroize;

#[derive(zeroize::Zeroize)]
#[zeroize(drop)]
pub struct LyreKeyPair {
    privkey: ArrayVec<u8, 32>,
    pubkey: ArrayVec<u8, 32>,
}

impl LyreKeyPair {
    pub fn new_key(&mut self) -> &mut Self {
        let mut csprng = OsRng {};
        let keypair: Keypair = Keypair::generate(&mut csprng);

        self.privkey[..].copy_from_slice(&keypair.secret.to_bytes());
        self.pubkey[..].copy_from_slice(&keypair.public.to_bytes());

        self
    }

    pub fn zero_privkey(&mut self) -> LyreOpsOutcome {
        self.privkey.zeroize();

        if self.privkey == ArrayVec::from([0_u8; 32]) {
            LyreOpsOutcome::ZeroingPrivKeyComplete
        } else {
            LyreOpsOutcome::ZeroingPrivKeyError
        }
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
            privkey: ArrayVec::from([0_u8; 32]),
            pubkey: ArrayVec::from([0_u8; 32]),
        }
    }
}

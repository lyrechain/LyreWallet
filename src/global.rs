use std::io::ErrorKind;

/// Print the output only for debug builds
/// Do not use in production as it leaks the secret data
pub trait DangerousDebugPrint {
    fn dangerous_debug(&self);
}

#[derive(Debug, PartialEq, Eq)]
pub enum LyreWalletOps {
    ///Useful for debugging
    KeySavedToDangerousStorage,
    LoadedKeyPair,
}

#[derive(Debug, PartialEq, Eq)]
pub enum StorageCipher {
    PlainBytes = 0x00,
    Base58 = 0x01,
    XChaCha20Blake3Aead = 0x02,
    XChaCha12Blake3Aead = 0x03,
    XChaCha8Blake3Aead = 0x04,
    UnsupportedCipher = 0x05,
}

pub type Result<T> = std::result::Result<T, LyreChainError>;

#[derive(Debug, PartialEq, Eq)]
pub enum LyreChainError {
    NotFound,
    PermissionDenied,
    ConnectionRefused,
    ConnectionReset,
    ConnectionAborted,
    NotConnected,
    AddrInUse,
    AddrNotAvailable,
    BrokenPipe,
    AlreadyExists,
    WouldBlock,
    InvalidInput,
    InvalidData,
    TimedOut,
    WriteZero,
    Interrupted,
    Other,
    UnexpectedEof,
    Unsupported,
    OutOfMemory,
    TryIntoU8_32LenError,
    UnsupportedError(String),
}

impl From<std::io::Error> for LyreChainError {
    fn from(error: std::io::Error) -> Self {
        match error.kind() {
            ErrorKind::NotFound => LyreChainError::NotFound,
            ErrorKind::PermissionDenied => LyreChainError::PermissionDenied,
            ErrorKind::ConnectionRefused => LyreChainError::ConnectionRefused,
            ErrorKind::ConnectionReset => LyreChainError::ConnectionReset,
            ErrorKind::ConnectionAborted => LyreChainError::ConnectionAborted,
            ErrorKind::NotConnected => LyreChainError::NotConnected,
            ErrorKind::AddrInUse => LyreChainError::AddrInUse,
            ErrorKind::AddrNotAvailable => LyreChainError::AddrNotAvailable,
            ErrorKind::BrokenPipe => LyreChainError::BrokenPipe,
            ErrorKind::AlreadyExists => LyreChainError::AlreadyExists,
            ErrorKind::WouldBlock => LyreChainError::WouldBlock,
            ErrorKind::InvalidInput => LyreChainError::InvalidInput,
            ErrorKind::InvalidData => LyreChainError::InvalidData,
            ErrorKind::TimedOut => LyreChainError::TimedOut,
            ErrorKind::WriteZero => LyreChainError::WriteZero,
            ErrorKind::Interrupted => LyreChainError::Interrupted,
            ErrorKind::Other => LyreChainError::Other,
            ErrorKind::UnexpectedEof => LyreChainError::UnexpectedEof,
            ErrorKind::Unsupported => LyreChainError::Unsupported,
            ErrorKind::OutOfMemory => LyreChainError::OutOfMemory,
            _ => LyreChainError::UnsupportedError(error.to_string()),
        }
    }
}

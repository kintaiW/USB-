
use std::error::Error;
use std::fmt::{Display, Formatter, Debug};

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum CryptoErrorKind {
    InvalidParameter,
    NotSupportUsage,
    RandError,
    UnpaddingNotMatch,
    InvalidPublicKey,
    InvalidPrivateKey,
    VerificationFailed,
    OuterErr,
    InnerErr,
}

impl Debug for CryptoErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoErrorKind::InvalidParameter => write!(f, "{}", "InvalidParameter"),
            CryptoErrorKind::NotSupportUsage => write!(f, "{}", "NotSupportUsage"),
            CryptoErrorKind::RandError => write!(f, "{}", "RandError"),
            CryptoErrorKind::UnpaddingNotMatch => write!(f, "{}", "UnpaddingNotMatch"),
            CryptoErrorKind::InvalidPublicKey => write!(f, "{}", "InvalidPublicKey"),
            CryptoErrorKind::InvalidPrivateKey => write!(f, "{}", "InvalidPrivateKey"),
            CryptoErrorKind::VerificationFailed => write!(f, "{}", "VerificationFailed"),
            CryptoErrorKind::OuterErr => write!(f, "{}", "OuterErr: ErrorsCausedByExternalModule"),
            CryptoErrorKind::InnerErr => write!(f, "{}", "InnerError"),
        }
    }
}

#[derive(Debug)]
pub struct CryptoError {
    kind: CryptoErrorKind,
    err: Box<dyn std::error::Error + Sync + Send>,
}

impl CryptoError {
    pub fn new<E>(kind: CryptoErrorKind, err: E) -> CryptoError 
        where E: Into<Box<dyn Error + Sync + Send>>{
        CryptoError {
            kind,
            err: err.into(),
        }
    }
    
    pub fn kind(&self) -> CryptoErrorKind {
        self.kind
    }
}

impl Display for CryptoError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}{}", self.kind, self.err)
    }
}

impl Error for CryptoError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.err.source()
    }
}

/// A trait for cryptography algorithms
pub trait Cipher {
    type Output;
    /// The cryptography algorithm used data block size(in bytes) for plaintext, `None` means that there is
    /// no requirement for the data block size.
    fn block_size(&self) -> Option<usize>;
    
    /// To encrypt the `data_block` and output the encrypted data `dst`, the length in bytes of
    /// the encrypted data will return if encrypt success, otherwise `CryptoError` returned.
    fn encrypt(&self, dst: &mut Vec<u8>, plaintext_block: &[u8]) -> Result<Self::Output, CryptoError>;
    
    /// To decrypt the `cipher_block` and output the decrypted data `dst`, the length in bytes of
    /// the decrypted data will return if decrypt success, other `CryptoError` returned.
    fn decrypt(&self, dst: &mut Vec<u8>, cipher_block: &[u8]) -> Result<Self::Output, CryptoError>;
}
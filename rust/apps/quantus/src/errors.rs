use alloc::string::String;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum QuantusError {
    #[error("Invalid transaction json")]
    InvalidTransaction,
    #[error("Invalid signing request: {0}")]
    InvalidEnvelope(String),
    #[error("This transaction is for {0}, which this wallet does not hold")]
    SignerMismatch(String),
    #[error("Sign failure: {0}")]
    SignFailure(String),
}

pub type Result<T> = core::result::Result<T, QuantusError>;


use alloc::string::String;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum QuantusError {
    #[error("Invalid transaction json")]
    InvalidTransaction,
    #[error("Sign failure: {0}")]
    SignFailure(String),
}

pub type Result<T> = core::result::Result<T, QuantusError>;


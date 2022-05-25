use std::{
    error::Error,
    fmt::{self, Display, Formatter},
};

use actix_http::{error::PayloadError, StatusCode};
use actix_web::{HttpResponse, ResponseError};

#[derive(Debug)]
pub struct CborError(serde_cbor::Error);

#[derive(Debug)]
pub enum CborPayloadError {
    OverflowKnownLength {
        length: usize,
        limit: usize,
    },
    /// Payload size is bigger than allowed. (default: 32kB)
    Overflow {
        limit: usize,
    },
    /// Content type error
    ContentType,
    /// Deserialize error
    Deserialize(serde_cbor::Error),
    /// Serialize error
    Serialize(serde_cbor::Error),
    /// Payload error
    Payload(PayloadError),
}

impl From<PayloadError> for CborPayloadError {
    fn from(e: PayloadError) -> Self {
        Self::Payload(e)
    }
}

impl Display for CborPayloadError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            CborPayloadError::OverflowKnownLength { length, limit } => write!(
                f,
                "CBOR payload ({} bytes) has exceeded the limit ({} bytes).",
                length, limit
            ),
            CborPayloadError::Overflow { limit } => {
                write!(f, "CBOR payload has exceeded limit ({} bytes).", limit)
            }
            CborPayloadError::ContentType => write!(f, "Content type error"),
            CborPayloadError::Deserialize(inner) => {
                write!(f, "CBOR deserialize error: {}", inner)
            }
            CborPayloadError::Serialize(inner) => write!(f, "CBOR serialize error: {}", inner),
            CborPayloadError::Payload(inner) => {
                write!(f, "Error that occur during reading payload: {:?}", inner)
            }
        }
    }
}

impl Error for CborPayloadError {}

/// Return `BadRequest` for `CborPayloadError`
impl ResponseError for CborPayloadError {
    fn error_response(&self) -> HttpResponse {
        match *self {
            CborPayloadError::Overflow { .. } => HttpResponse::new(StatusCode::PAYLOAD_TOO_LARGE),
            _ => HttpResponse::new(StatusCode::BAD_REQUEST),
        }
    }
}

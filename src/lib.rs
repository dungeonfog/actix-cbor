//! For CBOR helper documentation, see [`Cbor`].

use std::{
    fmt,
    future::Future,
    marker::PhantomData,
    ops,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use futures_util::{ready, Stream as _};
use serde::{de::DeserializeOwned, Serialize};

use actix_http::Payload;

#[cfg(feature = "__compress")]
use actix_web::dev::Decompress;
use actix_web::{
    body::EitherBody,
    error::Error,
    http::header::CONTENT_LENGTH,
    web::{self, BytesMut},
    FromRequest, HttpMessage, HttpRequest, HttpResponse, Responder,
};

pub mod error;
use error::CborPayloadError;

#[cfg(test)]
mod tests;

/// CBOR extractor and responder.
///
/// `Cbor` has two uses: CBOR responses, and extracting typed data from CBOR request payloads.
///
/// # Extractor
/// To extract typed data from a request body, the inner type `T` must implement the
/// [`serde::Deserialize`] trait.
///
/// Use [`CborConfig`] to configure extraction options.
///
/// ```
/// use actix_cbor::Cbor;
/// use serde::Deserialize;
///
/// #[derive(Deserialize)]
/// struct Info {
///     username: String,
/// }
///
/// /// deserialize `Info` from request's body
/// #[actix_web::post("/")]
/// async fn index(info: Cbor<Info>) -> String {
///     format!("Welcome {}!", info.username)
/// }
/// ```
///
/// # Responder
/// The `Cbor` type serializes CBOR formatted responses. A handler may return a value of type
/// `Cbor<T>` where `T` is the type of a structure to serialize into CBOR. The type `T` must
/// implement [`serde::Serialize`].
///
/// ```
/// use actix_web::{post, HttpRequest};
/// use actix_cbor::Cbor;
/// use serde::Serialize;
///
/// #[derive(Serialize)]
/// struct Info {
///     name: String,
/// }
///
/// #[post("/{name}")]
/// async fn index(req: HttpRequest) -> Cbor<Info> {
///     Cbor(Info {
///         name: req.match_info().get("name").unwrap().to_owned(),
///     })
/// }
/// ```
#[derive(Debug)]
pub struct Cbor<T>(pub T);

impl<T> Cbor<T> {
    /// Unwrap into inner `T` value.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> ops::Deref for Cbor<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T> ops::DerefMut for Cbor<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T: fmt::Display> fmt::Display for Cbor<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl<T: Serialize> Serialize for Cbor<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

/// Creates response with OK status code, correct content type header, and serialized CBOR payload.
///
/// If serialization failed
impl<T: Serialize> Responder for Cbor<T> {
    type Body = EitherBody<Vec<u8>>;

    fn respond_to(self, _: &HttpRequest) -> HttpResponse<Self::Body> {
        let mut buf = Vec::new();
        let body = match ciborium::ser::into_writer(&self.0, &mut buf) {
            Ok(()) => buf,
            Err(err) => {
                return HttpResponse::from_error(CborPayloadError::Serialize(err))
                    .map_into_right_body()
            }
        };
        match HttpResponse::Ok()
            .content_type("application/cbor")
            .message_body(body)
        {
            Ok(res) => res.map_into_left_body(),
            Err(err) => HttpResponse::from_error(err).map_into_right_body(),
        }
        // match serde_cbor::to_vec(&self.0) {
        //     Ok(body) => match HttpResponse::Ok()
        //         .content_type("application/cbor")
        //         .message_body(body)
        //     {
        //         Ok(res) => res.map_into_left_body(),
        //         Err(err) => HttpResponse::from_error(err).map_into_right_body(),
        //     },

        //     Err(err) => {
        //         HttpResponse::from_error(CborPayloadError::Serialize(err)).map_into_right_body()
        //     }
        // }
    }
}

/// See [here](#extractor) for example of usage as an extractor.
impl<T: DeserializeOwned> FromRequest for Cbor<T> {
    type Error = Error;
    type Future = CborExtractFut<T>;

    #[inline]
    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
        let config = CborConfig::from_req(req);

        let limit = config.limit;
        let ctype_required = config.content_type_required;
        let ctype_fn = config.content_type.as_deref();
        let err_handler = config.err_handler.clone();

        CborExtractFut {
            req: Some(req.clone()),
            fut: CborBody::new(req, payload, ctype_fn, ctype_required).limit(limit),
            err_handler,
        }
    }
}

type CborErrorHandler = Option<Arc<dyn Fn(CborPayloadError, &HttpRequest) -> Error + Send + Sync>>;

pub struct CborExtractFut<T> {
    req: Option<HttpRequest>,
    fut: CborBody<T>,
    err_handler: CborErrorHandler,
}

impl<T: DeserializeOwned> Future for CborExtractFut<T> {
    type Output = Result<Cbor<T>, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        let res = ready!(Pin::new(&mut this.fut).poll(cx));

        let res = match res {
            Err(err) => {
                let req = this.req.take().unwrap();
                log::debug!(
                    "Failed to deserialize Cbor from payload. \
                         Request path: {}",
                    req.path()
                );

                if let Some(err_handler) = this.err_handler.as_ref() {
                    Err((*err_handler)(err, &req))
                } else {
                    Err(err.into())
                }
            }
            Ok(data) => Ok(Cbor(data)),
        };

        Poll::Ready(res)
    }
}

/// `Cbor` extractor configuration.
///
/// # Examples
/// ```
/// use actix_web::{error, post, App, HttpResponse};
/// use actix_cbor::{Cbor, CborConfig};
/// use serde::Deserialize;
///
/// #[derive(Deserialize)]
/// struct Info {
///     name: String,
/// }
///
/// // `Cbor` extraction is bound by custom `CborConfig` applied to App.
/// #[post("/")]
/// async fn index(info: Cbor<Info>) -> String {
///     format!("Welcome {}!", info.name)
/// }
///
/// // custom `Cbor` extractor configuration
/// let cbor_cfg = CborConfig::default()
///     // limit request payload size
///     .limit(4096)
///     // only accept text/plain content type
///     .content_type(|mime| mime == mime::TEXT_PLAIN)
///     // use custom error handler
///     .error_handler(|err, req| {
///         error::InternalError::from_response(err, HttpResponse::Conflict().into()).into()
///     });
///
/// App::new()
///     .app_data(cbor_cfg)
///     .service(index);
/// ```
#[derive(Clone)]
pub struct CborConfig {
    limit: usize,
    err_handler: CborErrorHandler,
    content_type: Option<Arc<dyn Fn(mime::Mime) -> bool + Send + Sync>>,
    content_type_required: bool,
}

impl CborConfig {
    /// Set maximum accepted payload size. By default this limit is 2MB.
    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = limit;
        self
    }

    /// Set custom error handler.
    pub fn error_handler<F>(mut self, f: F) -> Self
    where
        F: Fn(CborPayloadError, &HttpRequest) -> Error + Send + Sync + 'static,
    {
        self.err_handler = Some(Arc::new(f));
        self
    }

    /// Set predicate for allowed content types.
    pub fn content_type<F>(mut self, predicate: F) -> Self
    where
        F: Fn(mime::Mime) -> bool + Send + Sync + 'static,
    {
        self.content_type = Some(Arc::new(predicate));
        self
    }

    /// Sets whether or not the request must have a `Content-Type` header to be parsed.
    pub fn content_type_required(mut self, content_type_required: bool) -> Self {
        self.content_type_required = content_type_required;
        self
    }

    /// Extract payload config from app data. Check both `T` and `Data<T>`, in that order, and fall
    /// back to the default payload config.
    fn from_req(req: &HttpRequest) -> &Self {
        req.app_data::<Self>()
            .or_else(|| req.app_data::<web::Data<Self>>().map(|d| d.as_ref()))
            .unwrap_or(&DEFAULT_CONFIG)
    }
}

const DEFAULT_LIMIT: usize = 2_097_152; // 2 mb

/// Allow shared refs used as default.
const DEFAULT_CONFIG: CborConfig = CborConfig {
    limit: DEFAULT_LIMIT,
    err_handler: None,
    content_type: None,
    content_type_required: true,
};

impl Default for CborConfig {
    fn default() -> Self {
        DEFAULT_CONFIG.clone()
    }
}

/// Future that resolves to some `T` when parsed from a CBOR payload.
///
/// Can deserialize any type `T` that implements [`Deserialize`][serde::Deserialize].
///
/// Returns error if:
/// - `Content-Type` is not `application/cbor` when `ctype_required` (passed to [`new`][Self::new])
///   is `true`.
/// - `Content-Length` is greater than [limit](CborBody::limit()).
/// - The payload, when consumed, is not valid CBOR.
pub enum CborBody<T> {
    Error(Option<CborPayloadError>),
    Body {
        limit: usize,
        /// Length as reported by `Content-Length` header, if present.
        length: Option<usize>,
        #[cfg(feature = "__compress")]
        payload: Decompress<Payload>,
        #[cfg(not(feature = "__compress"))]
        payload: Payload,
        buf: BytesMut,
        _res: PhantomData<T>,
    },
}

impl<T> Unpin for CborBody<T> {}

impl<T: DeserializeOwned> CborBody<T> {
    /// Create a new future to decode a CBOR request payload.
    #[allow(clippy::borrow_interior_mutable_const)]
    pub fn new(
        req: &HttpRequest,
        payload: &mut Payload,
        ctype_fn: Option<&(dyn Fn(mime::Mime) -> bool + Send + Sync)>,
        ctype_required: bool,
    ) -> Self {
        // check content-type
        let can_parse_cbor = if let Ok(Some(mime)) = req.mime_type() {
            mime.subtype().as_str() == "cbor"
                || mime.suffix().map(|n| n.as_str()) == Some("cbor")
                || ctype_fn.map_or(false, |predicate| predicate(mime))
        } else {
            // if `ctype_required` is false, assume payload is
            // cbor even when content-type header is missing
            !ctype_required
        };

        if !can_parse_cbor {
            return CborBody::Error(Some(CborPayloadError::ContentType));
        }

        let length = req
            .headers()
            .get(&CONTENT_LENGTH)
            .and_then(|l| l.to_str().ok())
            .and_then(|s| s.parse::<usize>().ok());

        // Notice the content-length is not checked against limit of cbor config here.
        // As the internal usage always call CborBody::limit after CborBody::new.
        // And limit check to return an error variant of CborBody happens there.

        let payload = {
            cfg_if::cfg_if! {
                if #[cfg(feature = "__compress")] {
                    Decompress::from_headers(payload.take(), req.headers())
                } else {
                    payload.take()
                }
            }
        };

        CborBody::Body {
            limit: DEFAULT_LIMIT,
            length,
            payload,
            buf: BytesMut::with_capacity(8192),
            _res: PhantomData,
        }
    }

    /// Set maximum accepted payload size. The default limit is 2MB.
    pub fn limit(self, limit: usize) -> Self {
        match self {
            CborBody::Body {
                length,
                payload,
                buf,
                ..
            } => {
                if let Some(len) = length {
                    if len > limit {
                        return CborBody::Error(Some(CborPayloadError::OverflowKnownLength {
                            length: len,
                            limit,
                        }));
                    }
                }

                CborBody::Body {
                    limit,
                    length,
                    payload,
                    buf,
                    _res: PhantomData,
                }
            }
            CborBody::Error(e) => CborBody::Error(e),
        }
    }
}

impl<T: DeserializeOwned> Future for CborBody<T> {
    type Output = Result<T, CborPayloadError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        match this {
            CborBody::Body {
                limit,
                buf,
                payload,
                ..
            } => loop {
                let res = ready!(Pin::new(&mut *payload).poll_next(cx));
                match res {
                    Some(chunk) => {
                        let chunk = chunk?;
                        let buf_len = buf.len() + chunk.len();
                        if buf_len > *limit {
                            return Poll::Ready(Err(CborPayloadError::Overflow { limit: *limit }));
                        } else {
                            buf.extend_from_slice(&chunk);
                        }
                    }
                    None => {
                        let value = ciborium::de::from_reader(&**buf)
                            .map_err(CborPayloadError::Deserialize)?;
                        return Poll::Ready(Ok(value));
                    }
                }
            },
            CborBody::Error(e) => Poll::Ready(Err(e.take().unwrap())),
        }
    }
}

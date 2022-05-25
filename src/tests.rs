use serde::{Deserialize, Serialize};

use actix_web::{
    body,
    error::InternalError,
    http::{
        header::{self, CONTENT_LENGTH, CONTENT_TYPE},
        StatusCode,
    },
    test::TestRequest,
    web::Bytes,
};

use super::*;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct MyObject {
    name: String,
}
impl MyObject {
    pub fn cbor() -> Vec<u8> {
        Self::cbor_with_name("test")
    }
    pub fn cbor_with_name(name: impl Into<String>) -> Vec<u8> {
        Self { name: name.into() }.to_cbor()
    }
    pub fn to_cbor(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(self, &mut buf).unwrap();
        buf
    }
}

fn cbor_eq(err: CborPayloadError, other: CborPayloadError) -> bool {
    match err {
        CborPayloadError::Overflow { .. } => {
            matches!(other, CborPayloadError::Overflow { .. })
        }
        CborPayloadError::OverflowKnownLength { .. } => {
            matches!(other, CborPayloadError::OverflowKnownLength { .. })
        }
        CborPayloadError::ContentType => matches!(other, CborPayloadError::ContentType),
        _ => false,
    }
}

#[actix_rt::test]
async fn test_responder() {
    let req = TestRequest::default().to_http_request();

    let obj = MyObject {
        name: "test".to_string(),
    };
    let cbor = obj.to_cbor();
    let j = Cbor(obj);
    let res = j.respond_to(&req);
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers().get(header::CONTENT_TYPE).unwrap(),
        header::HeaderValue::from_static("application/cbor")
    );
    assert_eq!(
        actix_http::body::to_bytes(res.into_body())
            .await
            .expect("error reading test response body"),
        Bytes::from(cbor)
    );
}

#[actix_rt::test]
async fn test_custom_error_responder() {
    let data = MyObject::cbor();
    let (req, mut pl) = TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/cbor"))
        .insert_header((header::CONTENT_LENGTH, data.len()))
        .set_payload(data)
        .app_data(CborConfig::default().limit(10).error_handler(|err, _| {
            let msg = MyObject {
                name: "invalid request".to_string(),
            };
            let resp = HttpResponse::BadRequest().body(msg.to_cbor());
            InternalError::from_response(err, resp).into()
        }))
        .to_http_parts();

    let s = Cbor::<MyObject>::from_request(&req, &mut pl).await;
    let resp = HttpResponse::from_error(s.unwrap_err());
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body = body::to_bytes(resp.into_body()).await.unwrap();
    let msg: MyObject = ciborium::de::from_reader(&*body).unwrap();
    assert_eq!(msg.name, "invalid request");
}

#[actix_rt::test]
async fn test_extract() {
    let data = MyObject::cbor();
    let (req, mut pl) = TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/cbor"))
        .insert_header((header::CONTENT_LENGTH, data.len()))
        .set_payload(data.clone())
        .to_http_parts();

    let s = Cbor::<MyObject>::from_request(&req, &mut pl).await.unwrap();
    assert_eq!(s.name, "test");
    assert_eq!(
        s.into_inner(),
        MyObject {
            name: "test".to_string()
        }
    );

    let (req, mut pl) = TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/cbor"))
        .insert_header((header::CONTENT_LENGTH, data.len()))
        .set_payload(data.clone())
        .app_data(CborConfig::default().limit(10))
        .to_http_parts();

    let s = Cbor::<MyObject>::from_request(&req, &mut pl).await;
    assert_eq!(
        s.unwrap_err().to_string(),
        "CBOR payload (11 bytes) has exceeded the limit (10 bytes)."
    );

    let (req, mut pl) = TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/cbor"))
        .insert_header((header::CONTENT_LENGTH, data.len()))
        .set_payload(data)
        .app_data(
            CborConfig::default()
                .limit(10)
                .error_handler(|_, _| CborPayloadError::ContentType.into()),
        )
        .to_http_parts();
    let s = Cbor::<MyObject>::from_request(&req, &mut pl).await;
    assert!(s.unwrap_err().to_string().contains("Content type error"));
}

#[actix_rt::test]
async fn test_cbor_body() {
    let (req, mut pl) = TestRequest::default().to_http_parts();
    let cbor = CborBody::<MyObject>::new(&req, &mut pl, None, true).await;
    assert!(cbor_eq(cbor.unwrap_err(), CborPayloadError::ContentType));

    let (req, mut pl) = TestRequest::default()
        .insert_header((
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/text"),
        ))
        .to_http_parts();
    let cbor = CborBody::<MyObject>::new(&req, &mut pl, None, true).await;
    assert!(cbor_eq(cbor.unwrap_err(), CborPayloadError::ContentType));

    let (req, mut pl) = TestRequest::default()
        .insert_header((
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/cbor"),
        ))
        .insert_header((
            header::CONTENT_LENGTH,
            header::HeaderValue::from_static("10000"),
        ))
        .to_http_parts();

    let json = CborBody::<MyObject>::new(&req, &mut pl, None, true)
        .limit(100)
        .await;
    assert!(cbor_eq(
        json.unwrap_err(),
        CborPayloadError::OverflowKnownLength {
            length: 10000,
            limit: 100
        }
    ));

    let (req, mut pl) = TestRequest::default()
        .insert_header((
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/cbor"),
        ))
        .set_payload(Bytes::from_static(&[0u8; 1000]))
        .to_http_parts();

    let cbor = CborBody::<MyObject>::new(&req, &mut pl, None, true)
        .limit(100)
        .await;

    assert!(cbor_eq(
        cbor.unwrap_err(),
        CborPayloadError::Overflow { limit: 100 }
    ));

    let data = MyObject::cbor();
    let (req, mut pl) = TestRequest::default()
        .insert_header((
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/cbor"),
        ))
        .insert_header((header::CONTENT_LENGTH, data.len()))
        .set_payload(data)
        .to_http_parts();

    let cbor = CborBody::<MyObject>::new(&req, &mut pl, None, true).await;
    assert_eq!(
        cbor.unwrap(),
        MyObject {
            name: "test".to_owned()
        }
    );
}

#[actix_rt::test]
async fn test_with_cbor_and_bad_content_type() {
    let data = MyObject::cbor();
    let (req, mut pl) = TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "text/plain"))
        .insert_header((header::CONTENT_LENGTH, data.len()))
        .set_payload(data)
        .app_data(CborConfig::default().limit(4096))
        .to_http_parts();

    let s = Cbor::<MyObject>::from_request(&req, &mut pl).await;
    assert!(s.is_err())
}

#[actix_rt::test]
async fn test_with_cbor_and_good_custom_content_type() {
    let data = MyObject::cbor();
    let (req, mut pl) = TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "text/plain"))
        .insert_header((header::CONTENT_LENGTH, data.len()))
        .set_payload(data)
        .app_data(CborConfig::default().content_type(|mime: mime::Mime| {
            mime.type_() == mime::TEXT && mime.subtype() == mime::PLAIN
        }))
        .to_http_parts();

    let s = Cbor::<MyObject>::from_request(&req, &mut pl).await;
    assert!(s.is_ok())
}

#[actix_rt::test]
async fn test_with_cbor_and_bad_custom_content_type() {
    let data = MyObject::cbor();
    let (req, mut pl) = TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "text/html"))
        .insert_header((header::CONTENT_LENGTH, data.len()))
        .set_payload(data)
        .app_data(CborConfig::default().content_type(|mime: mime::Mime| {
            mime.type_() == mime::TEXT && mime.subtype() == mime::PLAIN
        }))
        .to_http_parts();

    let s = Cbor::<MyObject>::from_request(&req, &mut pl).await;
    assert!(s.is_err())
}

#[actix_rt::test]
async fn test_cbor_with_no_content_type() {
    let data = MyObject::cbor();
    let (req, mut pl) = TestRequest::default()
        .insert_header((header::CONTENT_LENGTH, data.len()))
        .set_payload(data)
        .app_data(CborConfig::default().content_type_required(false))
        .to_http_parts();

    let s = Cbor::<MyObject>::from_request(&req, &mut pl).await;
    assert!(s.is_ok())
}

#[actix_rt::test]
async fn test_with_config_in_data_wrapper() {
    let data = MyObject::cbor();
    let (req, mut pl) = TestRequest::default()
        .insert_header((CONTENT_TYPE, "application/cbor"))
        .insert_header((CONTENT_LENGTH, data.len()))
        .set_payload(data)
        .app_data(web::Data::new(CborConfig::default().limit(10)))
        .to_http_parts();

    let s = Cbor::<MyObject>::from_request(&req, &mut pl).await;
    assert_eq!(
        s.unwrap_err().to_string(),
        "CBOR payload (11 bytes) has exceeded the limit (10 bytes)."
    );
}

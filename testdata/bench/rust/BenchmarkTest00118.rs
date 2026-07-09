use actix_web::{web, HttpResponse};

// Safe: Size limit check before deserialization
async fn handler(body: web::Bytes) -> HttpResponse {
    if body.len() > 1024 {
        return HttpResponse::PayloadTooLarge().body("too large");
    }
    let _value: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return HttpResponse::BadRequest().body("invalid"),
    };
    HttpResponse::Ok().body("ok")
}

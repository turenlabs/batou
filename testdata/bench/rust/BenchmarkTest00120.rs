use actix_web::{web, HttpResponse};
use serde::Deserialize;

#[derive(Deserialize)]
struct ValidatedPayload {
    action: String,
    count: u32,
}

// Safe: web::Json with typed struct plus manual validation
async fn handler(body: web::Json<ValidatedPayload>) -> HttpResponse {
    let payload = body.into_inner();
    if payload.count > 1000 {
        return HttpResponse::BadRequest().body("count too high");
    }
    HttpResponse::Ok().body(format!("action={} count={}", payload.action, payload.count))
}

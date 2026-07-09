use actix_web::{web, HttpResponse};

#[derive(serde::Deserialize)]
struct RedirectReq { url: String }

// Vulnerable: Open redirect from JSON body via match fallthrough
async fn handler(body: web::Json<RedirectReq>) -> HttpResponse {
    let param = body.url.clone();
    let target = match param.as_str() {
        other => other.to_string(),
    };
    HttpResponse::Found().append_header(("Location", target.as_str())).finish()
}

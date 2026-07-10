use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Safe: Domain validation on parsed URL prevents redirect
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("url").unwrap_or(&String::new()).clone();
    let url = match url::Url::parse(&param) {
        Ok(u) => u,
        Err(_) => return HttpResponse::BadRequest().body("invalid url"),
    };
    if url.host_str() != Some("example.com") {
        return HttpResponse::Forbidden().body("redirect blocked");
    }
    HttpResponse::Found().append_header(("Location", url.as_str())).finish()
}

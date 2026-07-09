use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Safe: text/plain content type prevents XSS
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("msg").unwrap_or(&String::new()).clone();
    HttpResponse::Ok().content_type("text/plain").body(param)
}

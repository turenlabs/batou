use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Vulnerable: Open redirect via TemporaryRedirect
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("redirect").unwrap_or(&String::new()).clone();
    HttpResponse::TemporaryRedirect().append_header(("Location", param.as_str())).finish()
}

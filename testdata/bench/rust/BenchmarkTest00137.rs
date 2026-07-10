use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Vulnerable: Open redirect via to_string chain
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("url").unwrap_or(&String::new()).clone();
    let u = param.to_string();
    HttpResponse::Found().append_header(("Location", u.as_str())).finish()
}

use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Vulnerable: Open redirect via Location header from user input
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("url").unwrap_or(&String::new()).clone();
    HttpResponse::Found().append_header(("Location", param.as_str())).finish()
}

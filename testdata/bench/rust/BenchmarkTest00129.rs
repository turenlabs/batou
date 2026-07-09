use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Vulnerable: Open redirect via variable indirection
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("dest").unwrap_or(&String::new()).clone();
    let url = param.clone();
    HttpResponse::Found().append_header(("Location", url.as_str())).finish()
}

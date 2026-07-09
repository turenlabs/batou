use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Vulnerable: Open redirect via string concat URL
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("domain").unwrap_or(&String::new()).clone();
    let url = String::from("https://") + &param;
    HttpResponse::Found().append_header(("Location", url.as_str())).finish()
}

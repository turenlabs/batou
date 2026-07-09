use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Safe: URL-encoded output prevents XSS
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("value").unwrap_or(&String::new()).clone();
    let encoded = urlencoding::encode(&param);
    let html = format!("<a href='/search?q={}'>Search</a>", encoded);
    HttpResponse::Ok().content_type("text/html").body(html)
}

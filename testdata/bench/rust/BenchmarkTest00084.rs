use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Safe: XSS prevented with html_escape encoding
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("msg").unwrap_or(&String::new()).clone();
    let escaped = html_escape::encode_text(&param);
    let html = format!("<div>{}</div>", escaped);
    HttpResponse::Ok().content_type("text/html").body(html)
}

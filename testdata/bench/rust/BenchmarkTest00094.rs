use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Safe: Integer-parsed value prevents XSS
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("count").unwrap_or(&String::new()).clone();
    let n: i64 = match param.parse() {
        Ok(v) => v,
        Err(_) => return HttpResponse::BadRequest().body("invalid number"),
    };
    let html = format!("<p>Count: {}</p>", n);
    HttpResponse::Ok().content_type("text/html").body(html)
}

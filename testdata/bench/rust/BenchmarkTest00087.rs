use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Vulnerable: XSS via img src attribute injection
async fn handler(form: web::Form<HashMap<String, String>>) -> HttpResponse {
    let param = form.get("avatar").unwrap_or(&String::new()).clone();
    let html = format!("<img src='{}'>", param);
    HttpResponse::Ok().content_type("text/html").body(html)
}

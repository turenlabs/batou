use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Vulnerable: Open redirect via SeeOther with format!
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("next").unwrap_or(&String::new()).clone();
    let url = format!("{}", param);
    HttpResponse::SeeOther().append_header(("Location", url.as_str())).finish()
}

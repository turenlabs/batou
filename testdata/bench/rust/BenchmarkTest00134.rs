use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Safe: Integer-based page redirect
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("page").unwrap_or(&String::new()).clone();
    let page: u32 = match param.parse() {
        Ok(v) => v,
        Err(_) => return HttpResponse::BadRequest().body("invalid page"),
    };
    let url = format!("/page/{}", page);
    HttpResponse::Found().append_header(("Location", url.as_str())).finish()
}

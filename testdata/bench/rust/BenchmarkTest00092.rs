use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Safe: Template engine with auto-escaping
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("name").unwrap_or(&String::new()).clone();
    let mut tera = tera::Tera::default();
    tera.autoescape_on(vec!["html"]);
    let mut ctx = tera::Context::new();
    ctx.insert("name", &param);
    // tera.render_str("<p>{{ name }}</p>", &ctx)
    HttpResponse::Ok().body("safe")
}

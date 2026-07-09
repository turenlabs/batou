use actix_web::{web, HttpResponse};

// Safe: Static file serve, no user input in path
async fn handler(_query: web::Query<()>) -> HttpResponse {
    let content = std::fs::read_to_string("static/index.html").unwrap_or_default();
    HttpResponse::Ok().body(content)
}

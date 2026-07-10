use actix_web::{web, HttpResponse};

// Safe: Static file response, no user input
async fn handler(_query: web::Query<()>) -> HttpResponse {
    let content = std::fs::read_to_string("static/page.html").unwrap_or_default();
    HttpResponse::Ok().content_type("text/html").body(content)
}

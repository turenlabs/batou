use actix_web::{web, HttpResponse};

// Safe: Hardcoded redirect target
async fn handler(_query: web::Query<()>) -> HttpResponse {
    HttpResponse::Found().append_header(("Location", "/dashboard")).finish()
}

use actix_web::{web, HttpResponse};

// Safe: Static redirect to login page
async fn handler(_query: web::Query<()>) -> HttpResponse {
    HttpResponse::Found().append_header(("Location", "/login")).finish()
}

use actix_web::{web, HttpResponse};

// Safe: Hardcoded HTML, no user input
async fn handler(_query: web::Query<()>) -> HttpResponse {
    let html = "<html><body>Hello World</body></html>";
    HttpResponse::Ok().content_type("text/html").body(html)
}

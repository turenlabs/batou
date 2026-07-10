use actix_web::{web, HttpResponse};

// Safe: Hardcoded URL, no user input
async fn handler(_query: web::Query<()>) -> HttpResponse {
    let resp = reqwest::get("https://api.example.com/health").await.unwrap();
    HttpResponse::Ok().body(resp.text().await.unwrap_or_default())
}

use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Safe: SQL injection prevented with rusqlite params
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("id").unwrap_or(&String::new()).clone();
    // conn.execute("SELECT * FROM users WHERE id = ?1", rusqlite::params![&param])
    HttpResponse::Ok().body("safe")
}

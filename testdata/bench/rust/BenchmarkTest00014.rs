use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Safe: SQL injection prevented by parsing to integer
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("id").unwrap_or(&String::new()).clone();
    let id: i64 = match param.parse() {
        Ok(v) => v,
        Err(_) => return HttpResponse::BadRequest().body("invalid id"),
    };
    let sql = format!("SELECT * FROM users WHERE id = {}", id);
    // sqlx::query(&sql).execute(&pool).await
    HttpResponse::Ok().body("safe")
}

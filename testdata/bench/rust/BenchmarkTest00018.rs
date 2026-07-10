use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Safe: SQL injection prevented with validated enum
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("sort").unwrap_or(&String::new()).clone();
    let column = match param.as_str() {
        "name" => "name",
        "date" => "created_at",
        "id" => "id",
        _ => return HttpResponse::BadRequest().body("invalid sort"),
    };
    let sql = format!("SELECT * FROM users ORDER BY {}", column);
    // sqlx::query(&sql).execute(&pool).await
    HttpResponse::Ok().body("safe")
}

use actix_web::{web, HttpResponse};

// Safe: SQL with hardcoded value, no user input in query
async fn handler(path: web::Path<String>) -> HttpResponse {
    let _param = path.into_inner();
    let id = "admin";
    let sql = format!("SELECT * FROM users WHERE role = '{}'", id);
    // sqlx::query(&sql).execute(&pool).await
    HttpResponse::Ok().body("safe")
}

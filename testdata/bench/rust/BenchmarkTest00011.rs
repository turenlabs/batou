use actix_web::{web, HttpResponse};

// Vulnerable: SQL injection via match pattern
async fn handler(path: web::Path<String>) -> HttpResponse {
    let category = path.into_inner();
    let sql = match category.as_str() {
        _ => format!("SELECT * FROM items WHERE category = '{}'", category),
    };
    // sqlx::query(&sql).execute(&pool).await
    HttpResponse::Ok().body(sql)
}

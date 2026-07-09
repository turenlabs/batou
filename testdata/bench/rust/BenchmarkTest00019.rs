use actix_web::{web, HttpResponse};

#[derive(serde::Deserialize)]
struct SearchReq { query: String }

// Vulnerable: SQL injection from JSON body
async fn handler(body: web::Json<SearchReq>) -> HttpResponse {
    let param = body.query.clone();
    let sql = format!("SELECT * FROM documents WHERE content LIKE '%{}%'", param);
    // sqlx::query(&sql).execute(&pool).await
    HttpResponse::Ok().body(sql)
}

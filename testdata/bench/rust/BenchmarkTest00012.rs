use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Safe: SQL injection prevented with sea_orm filter
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("name").unwrap_or(&String::new()).clone();
    // Entity::find().filter(Column::Name.eq(&param)).one(&db).await
    HttpResponse::Ok().body("safe")
}

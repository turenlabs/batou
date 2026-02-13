// Vulnerable Rust web handler - multiple security issues
use actix_web::{web, HttpResponse, HttpRequest};
use sqlx::PgPool;
use std::process::Command;

// RS-002: Command injection via shell invocation
async fn ping_host(query: web::Query<PingParams>) -> HttpResponse {
    let host = &query.host;
    let output = Command::new("sh")
        .arg("-c")
        .arg(format!("ping -c 3 {}", host))
        .output()
        .unwrap();
    HttpResponse::Ok().body(String::from_utf8_lossy(&output.stdout).to_string())
}

// RS-003: SQL injection via format! macro
async fn get_user(path: web::Path<String>, pool: web::Data<PgPool>) -> HttpResponse {
    let username = path.into_inner();
    let row = sqlx::query(&format!("SELECT * FROM users WHERE username = '{}'", username))
        .fetch_one(pool.get_ref())
        .await
        .unwrap();
    HttpResponse::Ok().json(row)
}

// RS-007: Panic in web handler via unwrap
async fn process_data(body: web::Json<DataRequest>, pool: web::Data<PgPool>) -> HttpResponse {
    let data = body.into_inner();
    let result = heavy_computation(&data).unwrap();
    let db_result = sqlx::query("INSERT INTO results (data) VALUES ($1)")
        .bind(&result)
        .execute(pool.get_ref())
        .await
        .expect("db insert failed");
    HttpResponse::Ok().json(db_result)
}

// RS-004: Path traversal - no validation
async fn read_file(query: web::Query<FileParams>) -> HttpResponse {
    let content = std::fs::read_to_string(&query.filename).unwrap();
    HttpResponse::Ok().body(content)
}

struct PingParams { host: String }
struct DataRequest { payload: String }
struct FileParams { filename: String }
fn heavy_computation(_data: &DataRequest) -> Result<String, String> { Ok("ok".into()) }

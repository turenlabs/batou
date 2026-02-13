// Safe Rust web handler - follows security best practices
use actix_web::{web, HttpResponse};
use sqlx::PgPool;
use std::process::Command;

// Safe: Direct command execution without shell, static program name
async fn ping_host(query: web::Query<PingParams>) -> Result<HttpResponse, actix_web::Error> {
    let host = &query.host;
    // Validate: only allow hostname characters
    if !host.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '-') {
        return Ok(HttpResponse::BadRequest().body("invalid host"));
    }
    let output = Command::new("ping")
        .arg("-c")
        .arg("3")
        .arg(host)
        .output()
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    Ok(HttpResponse::Ok().body(String::from_utf8_lossy(&output.stdout).to_string()))
}

// Safe: Parameterized SQL query with .bind()
async fn get_user(path: web::Path<String>, pool: web::Data<PgPool>) -> Result<HttpResponse, actix_web::Error> {
    let username = path.into_inner();
    let row = sqlx::query("SELECT * FROM users WHERE username = $1")
        .bind(&username)
        .fetch_one(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    Ok(HttpResponse::Ok().json(row))
}

// Safe: Proper error handling with ? operator instead of unwrap
async fn process_data(body: web::Json<DataRequest>, pool: web::Data<PgPool>) -> Result<HttpResponse, actix_web::Error> {
    let data = body.into_inner();
    let result = heavy_computation(&data)
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    sqlx::query("INSERT INTO results (data) VALUES ($1)")
        .bind(&result)
        .execute(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    Ok(HttpResponse::Ok().json(result))
}

// Safe: Path traversal prevention with canonicalize + starts_with
async fn read_file(query: web::Query<FileParams>) -> Result<HttpResponse, actix_web::Error> {
    let base_dir = std::path::Path::new("/var/data");
    let requested = base_dir.join(&query.filename);
    let canonical = requested.canonicalize()
        .map_err(|_| actix_web::error::ErrorNotFound("file not found"))?;
    if !canonical.starts_with(base_dir) {
        return Ok(HttpResponse::Forbidden().body("access denied"));
    }
    let content = std::fs::read_to_string(&canonical)
        .map_err(|_| actix_web::error::ErrorNotFound("file not found"))?;
    Ok(HttpResponse::Ok().body(content))
}

struct PingParams { host: String }
struct DataRequest { payload: String }
struct FileParams { filename: String }
fn heavy_computation(_data: &DataRequest) -> Result<String, String> { Ok("ok".into()) }

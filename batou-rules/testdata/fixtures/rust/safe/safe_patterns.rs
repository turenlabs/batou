use sqlx;

// SAFE: Parameterized query with bind
pub async fn find_user(pool: &sqlx::PgPool, username: &str) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT * FROM users WHERE username = $1")
        .bind(username)
        .execute(pool)
        .await?;
    Ok(())
}

// SAFE: Command::new with static program and separate args
use std::process::Command;

pub fn list_directory(dir: &str) -> std::io::Result<std::process::Output> {
    Command::new("ls")
        .arg("-la")
        .arg(dir)
        .output()
}

// SAFE: Proper error handling in handler
use actix_web::{web, HttpResponse, HttpRequest};

#[get("/user/{id}")]
async fn get_user(path: web::Path<String>) -> HttpResponse {
    let id = path.into_inner();
    match db.find_user(&id).await {
        Ok(user) => HttpResponse::Ok().json(user),
        Err(_) => HttpResponse::NotFound().finish(),
    }
}

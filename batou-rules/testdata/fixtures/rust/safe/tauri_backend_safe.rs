// Safe Tauri backend - demonstrates secure patterns for Tauri Rust code

use tauri::command;

// SAFE: Tauri command that validates input against allowlist
#[tauri::command]
fn run_allowed_program(name: String, args: Vec<String>) -> Result<String, String> {
    let allowed = ["ls", "echo", "date"];
    if !allowed.contains(&name.as_str()) {
        return Err("Program not in allowlist".to_string());
    }
    let output = std::process::Command::new("/usr/bin/env")
        .arg(&name)
        .args(&args)
        .output()
        .map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

// SAFE: Tauri command with fixed program path
#[tauri::command]
fn get_system_info() -> Result<String, String> {
    let output = std::process::Command::new("uname")
        .arg("-a")
        .output()
        .map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

// SAFE: Data retrieval command with no process spawning
#[tauri::command]
fn get_user(id: i32) -> Result<User, String> {
    let user = db::find_user(id).map_err(|e| e.to_string())?;
    Ok(user)
}

// SAFE: File read with path validation
#[tauri::command]
fn read_app_file(filename: String) -> Result<String, String> {
    // Only allow alphanumeric filenames in app data dir
    if !filename.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '-') {
        return Err("Invalid filename".to_string());
    }
    if filename.contains("..") {
        return Err("Path traversal detected".to_string());
    }
    let app_dir = tauri::api::path::app_data_dir(&tauri::Config::default())
        .ok_or("Cannot find app data dir")?;
    let path = app_dir.join(&filename);
    std::fs::read_to_string(path).map_err(|e| e.to_string())
}

// SAFE: Custom protocol with origin validation
fn setup_protocol(app: &mut tauri::App) {
    app.register_uri_scheme_protocol("myapp", |_app, request| {
        // Validate origin
        let origin = request.headers().get("Origin")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if origin != "tauri://localhost" {
            return tauri::http::ResponseBuilder::new()
                .status(403)
                .body(Vec::new());
        }
        let allowed_files = vec!["index.html", "style.css", "app.js"];
        let path = request.uri().path().trim_start_matches('/');
        if !allowed_files.contains(&path) {
            return tauri::http::ResponseBuilder::new()
                .status(404)
                .body(Vec::new());
        }
        let content = std::fs::read(format!("assets/{}", path)).unwrap_or_default();
        tauri::http::ResponseBuilder::new()
            .body(content)
    });
}

struct User {
    id: i32,
    name: String,
}

mod db {
    use super::User;
    pub fn find_user(id: i32) -> Result<User, String> {
        Ok(User { id, name: "test".to_string() })
    }
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            run_allowed_program,
            get_system_info,
            get_user,
            read_app_file,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

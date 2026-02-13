// Vulnerable Tauri backend - demonstrates common security issues in Tauri Rust code

use tauri::command;
use std::process::Command;

// VULN: Tauri command that directly executes user-provided program name
#[tauri::command]
fn run_command(program: String, args: Vec<String>) -> Result<String, String> {
    let output = std::process::Command::new(program)
        .args(&args)
        .output()
        .map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

// VULN: Tauri command with tokio process spawn from frontend input
#[tauri::command]
async fn async_execute(cmd: String) -> Result<String, String> {
    let output = tokio::process::Command::new(cmd)
        .output()
        .await
        .map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

// VULN: Shell open API used without restriction
#[tauri::command]
fn open_url(url: String) -> Result<(), String> {
    tauri::api::shell::open(&url).map_err(|e| e.to_string())
}

// VULN: Custom protocol handler without origin validation
fn setup_protocol(app: &mut tauri::App) {
    app.register_uri_scheme_protocol("custom", |_app, request| {
        let path = request.uri().path();
        let content = std::fs::read(path).unwrap_or_default();
        tauri::http::ResponseBuilder::new()
            .header("Access-Control-Allow-Origin", "*")
            .body(content)
    });
}

// VULN: Updater with insecure transport
fn setup_updater(app: tauri::AppHandle) -> Result<(), Box<dyn std::error::Error>> {
    let update = tauri::updater::builder(app)
        .dangerous_insecure_transport_protocol(true)
        .build()?;
    Ok(())
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            run_command,
            async_execute,
            open_url,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

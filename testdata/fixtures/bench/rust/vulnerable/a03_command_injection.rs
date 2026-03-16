// Source: CWE-78 - OS Command Injection via Command::new in Rust
// Expected: BATOU-RS
// OWASP: A03:2021 - Injection (Command Injection)

use std::env;
use std::process::Command;

fn run_ping(target: &str) {
    let output = Command::new("sh")
        .arg("-c")
        .arg(format!("ping -c 1 {}", target))
        .output()
        .expect("failed to execute");
    println!("{}", String::from_utf8_lossy(&output.stdout));
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        run_ping(&args[1]);
    }
}

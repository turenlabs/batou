// Source: CWE-89 - SQL Injection via format! in Rust
// Expected: BATOU-RUST
// OWASP: A03:2021 - Injection (SQL Injection)

use std::env;

fn find_user(username: &str) -> String {
    let query = format!("SELECT * FROM users WHERE name = '{}'", username);
    // db.execute(&query)
    query
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        let result = find_user(&args[1]);
        println!("{}", result);
    }
}

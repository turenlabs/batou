use std::process::Command;

// RS-002: Command injection via shell invocation
pub fn run_shell_command(user_input: &str) {
    Command::new("sh")
        .arg("-c")
        .arg(user_input)
        .output()
        .expect("failed to execute");
}

// RS-002: Command::new with format! macro
pub fn run_formatted_command(program: &str, args: &str) {
    Command::new(format!("/usr/bin/{}", program))
        .arg(args)
        .output()
        .expect("failed");
}

// RS-002: Command::new("bash") shell invocation
pub fn bash_command(script: &str) {
    Command::new("bash")
        .arg("-c")
        .arg(script)
        .spawn()
        .expect("failed");
}

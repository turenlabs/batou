// Source: CWE-78 - OS Command Injection via Process in Swift
// Expected: BATOU-INJ, TAINT
// OWASP: A03:2021 - Injection (Command Injection)

import Foundation

func runCommand(userInput: String) {
    let task = Process()
    task.executableURL = URL(fileURLWithPath: "/bin/sh")
    task.arguments = ["-c", "ping -c 1 " + userInput]
    try? task.run()
    task.waitUntilExit()
}

let args = CommandLine.arguments
if args.count > 1 {
    runCommand(userInput: args[1])
}

// Source: CWE-78 - OS Command Injection via Runtime.exec in Kotlin
// Expected: BATOU-INJ, TAINT
// OWASP: A03:2021 - Injection (Command Injection)

package com.example.util

fun executeCommand(userInput: String) {
    val cmd = "ping -c 1 $userInput"
    val process = Runtime.getRuntime().exec(cmd)
    val output = process.inputStream.bufferedReader().readText()
    println(output)
}

fun main(args: Array<String>) {
    val host = args.firstOrNull() ?: return
    executeCommand(host)
}

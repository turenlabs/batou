// Source: CWE-78 - OS Command Injection via GString execute in Groovy
// Expected: BATOU-GVY
// OWASP: A03:2021 - Injection (Command Injection)

def userInput = args[0]
"ping -c 1 ${userInput}".execute()

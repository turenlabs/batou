// Source: CWE-798 - Hardcoded API keys and credentials in Swift
// Expected: BATOU-SWIFT
// OWASP: A02:2021 - Cryptographic Failures (Hardcoded Secrets)

import Foundation

let API_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
let DATABASE_PASSWORD = "SuperSecretPass123!"
let AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

func connectToAPI() {
    let url = URL(string: "https://api.example.com/data")!
    var request = URLRequest(url: url)
    request.setValue("Bearer \(API_KEY)", forHTTPHeaderField: "Authorization")
}

func connectToDB() {
    let connStr = "postgresql://admin:\(DATABASE_PASSWORD)@db.example.com/prod"
    print(connStr)
}

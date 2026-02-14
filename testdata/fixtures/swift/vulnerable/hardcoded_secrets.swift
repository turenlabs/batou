import Foundation

// VULNERABLE: Hardcoded API key
class APIClient {
    let apiKey = "sk_live_Rk3jF7nL9pQ2mW8xT4vY6hB1dC5gA0eZ"

    func makeRequest(endpoint: String) {
        var request = URLRequest(url: URL(string: endpoint)!)
        request.setValue(apiKey, forHTTPHeaderField: "Authorization")
        URLSession.shared.dataTask(with: request).resume()
    }
}

// VULNERABLE: Hardcoded password
func connectToDatabase() {
    let password = "SuperSecretDBPass123!"
    let connectionString = "postgresql://admin:\(password)@db.example.com:5432/prod"
    print(connectionString)
}

// VULNERABLE: Hardcoded AWS key
func uploadToS3() {
    let accessKey = "AKIAIOSFODNN7EXAMPLE"
    let secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    print(accessKey, secretKey)
}

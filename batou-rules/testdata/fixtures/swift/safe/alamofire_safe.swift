import Alamofire
import Foundation

// Safe Alamofire usage with proper SSRF mitigations

func fetchProfileSafe(userId: String) {
    // Safe: hardcoded base URL, only userId is dynamic (integer-validated)
    guard let id = Int(userId) else { return }
    let url = "https://api.example.com/users/\(id)"
    AF.request(url).responseDecodable(of: UserProfile.self) { response in
        handleProfile(response)
    }
}

func fetchWithCertPinning(endpoint: String) {
    // Safe: certificate pinning via ServerTrustManager restricts connections
    let evaluators: [String: ServerTrustEvaluating] = [
        "api.example.com": PinnedCertificatesTrustEvaluator()
    ]
    let trustManager = ServerTrustManager(evaluators: evaluators)
    let session = Session(serverTrustManager: trustManager)
    session.request(endpoint).responseData { response in
        handleData(response)
    }
}

func fetchWithURLAllowlist(userUrl: String) {
    // Safe: URL validated against allowlist before request
    guard let url = URL(string: userUrl),
          let host = url.host,
          allowedHosts.contains(host) else {
        return
    }
    AF.request(userUrl).responseJSON { response in
        handleJSON(response)
    }
}

func fetchWithSchemeCheck(inputUrl: String) {
    // Safe: URL scheme validation restricts to HTTPS
    guard let url = URL(string: inputUrl),
          url.scheme == "https" else {
        return
    }
    AF.download(inputUrl).responseData { response in
        handleData(response)
    }
}

func uploadWithParameterEncoding(data: [String: String]) {
    // Safe: hardcoded URL, parameters properly encoded
    let encoder = URLEncodedFormParameterEncoder()
    AF.upload(
        multipartFormData: { form in
            for (key, value) in data {
                form.append(Data(value.utf8), withName: key)
            }
        },
        to: "https://api.example.com/upload"
    ).responseDecodable(of: UploadResponse.self) { response in
        handleUpload(response)
    }
}

func fetchWithInterceptor(url: String) {
    // Safe: RequestInterceptor enforces URL validation
    let interceptor = URLAllowlistInterceptor()
    AF.request(url, interceptor: interceptor).responseData { response in
        handleData(response)
    }
}

class URLAllowlistInterceptor: RequestInterceptor {
    func adapt(_ urlRequest: URLRequest, for session: Session, completion: @escaping (Result<URLRequest, Error>) -> Void) {
        guard let host = urlRequest.url?.host,
              allowedHosts.contains(host) else {
            completion(.failure(AFError.urlRequestValidationFailed(reason: .bodyDataInGETRequest(Data()))))
            return
        }
        completion(.success(urlRequest))
    }
}

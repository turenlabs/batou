import Alamofire
import Foundation
import Vapor

// SSRF (CWE-918): user-controlled URLs from a Vapor request flow into
// third-party HTTP-client / image-loader sinks. Each case is a confirmed
// source -> sink dataflow (Vapor req.query is the taint source).

// Vulnerable: tainted URL -> Alamofire AF.request
func fetchUserProfile(req: Request) {
    let userUrl = req.query["url"] ?? ""
    AF.request(userUrl).responseDecodable(of: UserProfile.self) { response in
        switch response.result {
        case .success(let profile):
            displayProfile(profile)
        case .failure(let error):
            print("Error: \(error)")
        }
    }
}

// Vulnerable: tainted URL -> Alamofire AF.download
func downloadUserFile(req: Request) {
    let urlParam = req.query["file_url"] ?? ""
    AF.download(urlParam).responseData { response in
        if let data = response.value {
            saveFile(data)
        }
    }
}

// Vulnerable: tainted URL -> Alamofire AF.upload (URL as first arg)
func uploadToUserServer(req: Request, fileData: Data) {
    let targetUrl = req.query["target"] ?? ""
    AF.upload(targetUrl, to: targetUrl).responseString { response in
        print(response.value ?? "")
    }
}

// Vulnerable: tainted URL -> Alamofire Session.request
func fetchWithSession(req: Request) {
    let endpoint = req.query["endpoint"] ?? ""
    let session = Session.default
    session.request(endpoint).responseJSON { response in
        handleJSON(response)
    }
}

// Vulnerable: tainted URL -> Alamofire Session.download
func downloadWithSession(req: Request) {
    let url = req.query["src"] ?? ""
    let session = Session()
    session.download(url).responseData { response in
        handleData(response)
    }
}

// Vulnerable: tainted URL -> AsyncHTTPClient request
func fetchWithAsyncHTTP(req: Request) {
    let url = req.query["proxy"] ?? ""
    let httpClient = HTTPClient(eventLoopGroupProvider: .singleton)
    httpClient.execute(request: try! HTTPClient.Request(url: url))
}

// Vulnerable: tainted URL -> SDWebImage sd_setImage(with:)
func loadSDImage(req: Request) {
    let imageUrl = req.query["avatar"] ?? ""
    imageView.sd_setImage(with: imageUrl)
}

// Vulnerable: tainted URL -> URLSession async data(from:) (SSRF)
func proxyFetch(req: Request) async throws -> Data {
    let raw = req.query["dest"] ?? ""
    let targetURL = URL(string: raw)!
    let (data, _) = try await URLSession.shared.data(from: targetURL)
    return data
}

import Alamofire
import Foundation

// SSRF via Alamofire - user-controlled URL passed to HTTP client

func fetchUserProfile(userUrl: String) {
    // Vulnerable: user-controlled URL passed directly to AF.request
    AF.request(userUrl).responseDecodable(of: UserProfile.self) { response in
        switch response.result {
        case .success(let profile):
            displayProfile(profile)
        case .failure(let error):
            print("Error: \(error)")
        }
    }
}

func downloadUserFile(urlParam: String) {
    // Vulnerable: user-controlled URL passed to AF.download
    AF.download(urlParam).responseData { response in
        if let data = response.value {
            saveFile(data)
        }
    }
}

func uploadToUserServer(targetUrl: String, fileData: Data) {
    // Vulnerable: user-controlled URL passed to AF.upload
    AF.upload(fileData, to: targetUrl).responseString { response in
        print(response.value ?? "")
    }
}

func fetchWithSession(endpoint: String) {
    let session = Session.default
    // Vulnerable: user-controlled URL passed to session.request
    session.request(endpoint).responseJSON { response in
        handleJSON(response)
    }
}

func downloadWithSession(url: String) {
    let session = Session()
    // Vulnerable: user-controlled URL passed to session.download
    session.download(url).responseData { response in
        handleData(response)
    }
}

func fetchViaMoya(targetId: String) {
    let provider = MoyaProvider<MyAPI>()
    // Vulnerable: provider.request with dynamic target
    provider.request(.user(id: targetId)) { result in
        switch result {
        case .success(let response):
            handleResponse(response.data)
        case .failure:
            break
        }
    }
}

func fetchWithAsyncHTTP(url: String) {
    let httpClient = HTTPClient(eventLoopGroupProvider: .singleton)
    // Vulnerable: user-controlled URL in AsyncHTTPClient
    httpClient.execute(request: try! HTTPClient.Request(url: url))
}

func loadImage(imageUrl: String) {
    let url = URL(string: imageUrl)!
    // Vulnerable: user-controlled URL in Kingfisher image loading
    imageView.kf.setImage(with: url)
}

func loadSDImage(imageUrl: String) {
    let url = URL(string: imageUrl)!
    // Vulnerable: user-controlled URL in SDWebImage
    imageView.sd_setImage(with: url)
}

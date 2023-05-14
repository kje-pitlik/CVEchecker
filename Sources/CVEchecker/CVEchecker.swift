import Alamofire
import Foundation


struct CVE: Codable {
    let package: String
    let after: String
}

struct CVEModel: Codable {
    let cveId: String
    let package: String
    let description: String
}

class CVEService {
    private let baseURL = "https://access.redhat.com/labs/securitydataapi/cve.json"
    
    func getCVEs(cve: CVE, completion: @escaping ([CVEModel]?, Error?) -> Void) {
        guard let url = URL(string: baseURL) else {
            completion(nil, NSError(domain: "URLError", code: 0, userInfo: [NSLocalizedDescriptionKey: "Failed to create URL"]))
            return
        }
        
        AF.request(url, method: .get, parameters: cve, encoder: URLEncodedFormParameterEncoder.default).responseDecodable(of: [CVEModel].self) { response in
            switch response.result {
            case .success(let value):
                completion(value, nil)
            case .failure(let error):
                completion(nil, error)
            }
        }
    }
}

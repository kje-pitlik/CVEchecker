import Alamofire
import Foundation

public struct CVE: Codable {
    public let id: String
    public let cvssScore: Double
    public let publishedDate: String
    public let cwe: String
    public let summary: String
}

public struct CVEchecker {
    public init() {}
    
    public func getCVEs(package: String, after: String, completion: @escaping ([CVE]?, Error?) -> Void) {
        let baseURL = "https://access.redhat.com/labs/securitydataapi/cve.json"
        let parameters: Parameters = ["package": package, "after": after]
        AF.request(baseURL, parameters: parameters).responseJSON { response in
            switch response.result {
            case .success(let value):
                do {
                    let decoder = JSONDecoder()
                    let cves = try decoder.decode([CVE].self, from: response.data!)
                    completion(cves, nil)
                } catch let error {
                    completion(nil, error)
                }
            case .failure(let error):
                completion(nil, error)
            }
        }
    }
}

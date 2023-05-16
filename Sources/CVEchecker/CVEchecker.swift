import Alamofire
import Foundation

public struct CVE: Codable {
    let name: String
    let cvss3Score: Double
    let severity: String
    let description: String
    let publishedDate: String
    let modifiedDate: String
}

public struct CVEchecker {
    public init() {}

    public func getCVEs(package: String, after: String, completion: @escaping ([CVE]?, Error?) -> Void) {
        let baseURL = "https://access.redhat.com/labs/securitydataapi/cve.json"
        let parameters: Parameters = ["package": package, "after": after]
        AF.request(baseURL, parameters: parameters).responseJSON { response in
            switch response.result {
            case .success(let value):
                if let cves = value as? [[String: Any]] {
                do {
                    let decoder = JSONDecoder()
                    let cves = try decoder.decode([CVE].self, from: response.data!)
                    completion(cves, nil)
                } else {
                    let error = NSError(domain: "ParsingError", code: 0, userInfo: [NSLocalizedDescriptionKey: "Failed to parse JSON object: \(value)"])
                } catch let error {
                    completion(nil, error)
                }
            case .failure(let error):
                completion(nil, error)
            }
        }
    }


}

import Alamofire
import Foundation

public struct CVE: Codable {
    public let CVE: String
    public let severity: String
    public let public_date: String
    public let advisories: [String]
    public let bugzilla: String
    public let bugzilla_description: String
    public let cvss_score: Double?
    public let cvss_scoring_vector: String?
    public let CWE: String?
    public let affected_packages: [String]
    public let resource_url: String
    public let cvss3_scoring_vector: String
    public let cvss3_score: String
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
                } catch {
                    completion(nil, error)
                }
            case .failure(let error):
                completion(nil, error)
            }
        }
    }
}


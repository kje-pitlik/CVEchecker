import Alamofire
import Foundation

public struct CVE: Codable {
    public let cve: String
    public let severity: String
    public let publicDate: String
    public let advisories: [String]
    public let bugzilla: String
    public let bugzillaDescription: String
    public let cvssScore: Double?
    public let cvssScoringVector: String?
    public let cwe: String
    public let affectedPackages: [String]
    public let resourceURL: String
    public let cvss3ScoringVector: String
    public let cvss3Score: String

    private enum CodingKeys: String, CodingKey {
        case cve = "CVE"
        case severity
        case publicDate = "public_date"
        case advisories
        case bugzilla
        case bugzillaDescription = "bugzilla_description"
        case cvssScore = "cvss_score"
        case cvssScoringVector = "cvss_scoring_vector"
        case cwe = "CWE"
        case affectedPackages = "affected_packages"
        case resourceURL = "resource_url"
        case cvss3ScoringVector = "cvss3_scoring_vector"
        case cvss3Score = "cvss3_score"
    }
}









public struct CVEchecker {
    public init() {}
    
    public func getCVEs(package: String, after: String, completion: @escaping ([CVE]?, Error?) -> Void) {
        let baseURL = "https://access.redhat.com/labs/securitydataapi/cve.json"
        let parameters: Alamofire.Parameters = ["package": package, "after": after]
        AF.request(baseURL, parameters: parameters).validate().responseJSON { response in
            switch response.result {
            case .success(let value):
                do {
                    let decoder = JSONDecoder()
                    decoder.keyDecodingStrategy = .convertFromSnakeCase
                    let cves = try decoder.decode([CVE].self, from: response.data!)
                    completion(cves, nil)
                
                } catch let DecodingError.dataCorrupted(context) {
                    print(context)
                } catch let DecodingError.keyNotFound(key, context) {
                    print("Key '\(key)' not found:", context.debugDescription)
                    print("codingPath:", context.codingPath)
                } catch let DecodingError.valueNotFound(value, context) {
                    print("Value '\(value)' not found:", context.debugDescription)
                    print("codingPath:", context.codingPath)
                } catch let DecodingError.typeMismatch(type, context)  {
                    print("Type '\(type)' mismatch:", context.debugDescription)
                    print("codingPath:", context.codingPath)
                } catch {
                    print("error: ", error)
                }


            case .failure(let error):
                completion(nil, error)
            }
        }
    }
}

// mi kellene meg gettelni? https://access.redhat.com/documentation/en-us/red_hat_security_data_api/1.0/html-single/red_hat_security_data_api/index#parameters_2
// Mitigation: A way to fix or reduce the problem without updated software.
// Details: Details about the flaw, possibly from Red Hat or Mitre.
// Acknowledgements: People or organizations that are being recognized.


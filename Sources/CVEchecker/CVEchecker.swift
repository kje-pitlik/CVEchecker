import Alamofire
import Foundation

public struct CVE: Codable {
    let CVE: String?
    let severity: String?
    let advisories: [String]?
    let bugzilla: String?
    let bugzilla_description: String?
    let cvss_score: String?
    let cvss_scoring_vector: String?
    let CWE: String?
    let affected_packages: [String]?
    let resource_url: String?
    let cvss3_scoring_vector: String?
    let cvss3_score: String?
    let publicDate: String?

    private enum CodingKeys: String, CodingKey {
        case publicDate = "public_date"
        case CVE = "CVE"
        case severity = "severity"
        case advisories = "advisories"
        case bugzilla = "bugzilla"
        case bugzilla_description = "bugzilla_description"
        case cvss_score = "cvss_score"
        case cvss_scoring_vector = "cvss_scoring_vector"
        case CWE = "CWE"
        case affected_packages = "affected_packages"
        case resource_url = "resource_url"
        case cvss3_scoring_vector = "cvss3_scoring_vector"
        case cvss3_score = "cvss3_score"
            // Define other coding keys for the remaining properties
        }
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        CVE = try container.decodeIfPresent(String.self, forKey: .CVE)
        severity = try container.decodeIfPresent(String.self, forKey: .severity)
        publicDate = try container.decodeIfPresent(String.self, forKey: .publicDate)

        advisories = try container.decodeIfPresent([String].self, forKey: .advisories)
        bugzilla = try container.decodeIfPresent(String.self, forKey: .bugzilla)
        bugzilla_description = try container.decodeIfPresent(String.self, forKey: .bugzilla_description)
        cvss_score = try container.decodeIfPresent(String.self, forKey: .cvss_score)
        cvss_scoring_vector = try container.decodeIfPresent(String.self, forKey: .cvss_scoring_vector)
        CWE = try container.decodeIfPresent(String.self, forKey: .CWE)
        affected_packages = try container.decodeIfPresent([String].self, forKey: .affected_packages)
        resource_url = try container.decodeIfPresent(String.self, forKey: .resource_url)
        cvss3_scoring_vector = try container.decodeIfPresent(String.self, forKey: .cvss3_scoring_vector)
        cvss3_score = try container.decodeIfPresent(String.self, forKey: .cvss3_score)
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
                    print("Key '\(key.stringValue)' not found:", context.debugDescription)
                    if let data = try? JSONSerialization.data(withJSONObject: value, options: .prettyPrinted),
                       let jsonString = String(data: data, encoding: .utf8) {
                        print("JSON response: \(jsonString)")
                    }
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


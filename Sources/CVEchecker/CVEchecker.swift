import Alamofire
import Foundation

public struct CVE: Codable {
    public let CVE: String
    public let severity: String
    public let public_date: String?
    public let advisories: [String]
    public let bugzilla: String
    public let bugzilla_description: String?
    public let cvss_score: String?
    public let cvss_scoring_vector: String?
    public let CWE: String
    public let affected_packages: [String]?
    public let resource_url: String?
    public let cvss3_scoring_vector: String?
    public let cvss3_score: String?

    private enum CodingKeys: String, CodingKey {
        case CVE, severity, public_date, advisories, bugzilla, bugzilla_description, cvss_score, cvss_scoring_vector, CWE, affected_packages, resource_url, cvss3_scoring_vector, cvss3_score
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        CVE = try container.decode(String.self, forKey: .CVE)
        severity = try container.decode(String.self, forKey: .severity)
        public_date = try container.decode(String.self, forKey: .public_date)
        advisories = try container.decode([String].self, forKey: .advisories)
        bugzilla = try container.decode(String.self, forKey: .bugzilla)
        bugzilla_description = try container.decodeIfPresent(String.self, forKey: .bugzilla_description)
        cvss_score = try container.decodeIfPresent(String.self, forKey: .cvss_score)
        cvss_scoring_vector = try container.decodeIfPresent(String.self, forKey: .cvss_scoring_vector)
        CWE = try container.decode(String.self, forKey: .CWE)
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


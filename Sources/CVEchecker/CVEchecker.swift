import Alamofire
import Foundation

public struct CVE: Codable {
    public let CVE: String
    public let cvss3_score: Double
    public let public_date: String
    public let CWE: String
    public let bugzilla_description: String
    public let severity: String

    private enum CodingKeys: String, CodingKey {
        case CVE, cvss3_score, public_date = "public_date", CWE, bugzilla_description, severity
    }
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
                    print("Error decoding JSON: \(error.localizedDescription)")
                    print("JSON response: \(String(data: response.data!, encoding: .utf8) ?? "nil")")
                    completion(nil, error)
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



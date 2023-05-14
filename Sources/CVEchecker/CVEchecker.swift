import Alamofire
import Foundation
public class CVE: Codable {
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
    public let resourceUrl: String
    public let cvss3ScoringVector: String
    public let cvss3Score: Double
    
    enum CodingKeys: String, CodingKey {
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
        case resourceUrl = "resource_url"
        case cvss3ScoringVector = "cvss3_scoring_vector"
        case cvss3Score = "cvss3_score"
    }
}
public struct CVEchecker {
    public init() {}
    
    public func getCVEs(completion: @escaping ([CVE]?, Error?) -> Void) {
        let url = URL(string: "https://example.com/cve_data.json")! // Replace with your URL
        
        URLSession.shared.dataTask(with: url) { data, _, error in
            guard let data = data else {
                completion(nil, error)
                return
            }
            
            do {
                let decoder = JSONDecoder()
                decoder.keyDecodingStrategy = .convertFromSnakeCase
                let cves = try decoder.decode([CVE].self, from: data)
                completion(cves, nil)
            } catch {
                completion(nil, error)
            }
        }.resume()
    }
}

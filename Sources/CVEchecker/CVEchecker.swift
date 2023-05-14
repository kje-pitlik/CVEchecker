import Alamofire
import Foundation

public struct CVEchecker {
    public init() {}
    
    public func getCVEs(package: String, after: String, completion: @escaping ([[String: Any]]?, Error?) -> Void) {
        let baseURL = "https://access.redhat.com/labs/securitydataapi/cve.json"
        let parameters: Parameters = ["package": package, "after": after]
        AF.request(baseURL, parameters: parameters).responseJSON { response in
            switch response.result {
            case .success(let value):
                guard let jsonData = try? JSONSerialization.data(withJSONObject: value, options: []) else {
                    completion(nil, NSError(domain: "ParsingError", code: 0, userInfo: [NSLocalizedDescriptionKey: "Failed to convert JSON object to data"]))
                    return
                }

                do {
                    if let cves = try JSONSerialization.jsonObject(with: jsonData, options: []) as? [[String: Any]] {
                        completion(cves, nil)
                    } else {
                        completion(nil, NSError(domain: "ParsingError", code: 0, userInfo: [NSLocalizedDescriptionKey: "Failed to parse JSON object"]))
                    }
                } catch {
                    completion(nil, error)
                }

            case .failure(let error):
                completion(nil, error)
            }
        }
    }

}

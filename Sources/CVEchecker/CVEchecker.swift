import Alamofire
import Foundation

public struct CVEchecker {
    public init() {}
    
    public func getCVEs(package: String, after: String, completion: @escaping ([String: Any]?, Error?) -> Void) {
        let baseURL = "https://access.redhat.com/labs/securitydataapi/cve.json"
        let parameters: Parameters = ["package": package, "after": after]
        AF.request(baseURL, parameters: parameters).responseJSON { response in
            switch response.result {
            case .success(let value):
                if let cves = value as? [String: Any] {
                    completion(cves, nil)
                } else {
                    completion(nil, NSError(domain: "ParsingError", code: 0, userInfo: nil))
                }
            case .failure(let error):
                completion(nil, error)
            }
        }
    }
}

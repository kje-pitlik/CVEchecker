import Alamofire
import Foundation

public struct CVEchecker {
    public init() {}
    
    func getCVEs(cve: CVE, completion: @escaping ([CVEModel]?, Error?) -> Void) {
        let parameters: Parameters = ["package": cve.package, "after": cve.after]
        let baseURL = "https://access.redhat.com/labs/securitydataapi/cve.json"
        
        AF.request(baseURL, parameters: parameters).responseJSON { response in
            switch response.result {
            case .success(let value):
                guard let jsonData = try? JSONSerialization.data(withJSONObject: value, options: []) else {
                    completion(nil, NSError(domain: "ParsingError", code: 0, userInfo: [NSLocalizedDescriptionKey: "Failed to convert JSON object to data"]))
                    return
                }
                
                do {
                    let decoder = JSONDecoder()
                    let cveModels = try decoder.decode([CVEModel].self, from: jsonData)
                    completion(cveModels, nil)
                } catch {
                    completion(nil, error)
                }
                
            case .failure(let error):
                completion(nil, error)
            }
        }
    }
}

struct CVE {
    let package: String
    let after: String
}
struct CVEModel: Decodable {
    let cveId: String
    let package: String
    let description: String
}

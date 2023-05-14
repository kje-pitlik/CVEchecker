//
//  API.swift
//  
//
//  Created by sdev on 2023. 05. 14..
//

import Foundation
import Alamofire

class API {
    
    static let shared = MyAPI()
    let baseURL = "https://access.redhat.com/labs/securitydataapi/cve.json"
    
    func getCVEs(completion: @escaping ([String: Any]?, Error?) -> Void) {
        let parameters: Parameters = ["package": "ios", "after": "2000-01-01"]
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

import Alamofire
import Foundation

public struct CVE: Codable {
    let cve: String
    let severity: String
    let publicDate: String
    let advisories: [String]
    let bugzilla: String
    let bugzillaDescription: String
    let cvssScore: Double?
    let cvssScoringVector: String?
    let CWE: String
    let affectedPackages: [String]
    let resourceUrl: String
    let cvss3ScoringVector: String
    let cvss3Score: Double
}

public struct CVEchecker {
    public init() {}
    
    func getCVEs(package: String, after: String, completion: @escaping ([CVE]) -> Void) {
        // Define the URL to retrieve the data from
        let urlString = "https://access.redhat.com/labs/securitydataapi/cve.json?package=\(package)&after=\(after)"
        
        // Create a URL object from the string
        guard let url = URL(string: urlString) else {
            print("Error: Invalid URL")
            return
        }
        
        // Create a URLSession and a data task to retrieve the JSON data
        let session = URLSession.shared
        let task = session.dataTask(with: url) { data, response, error in
            // Check for errors
            if let error = error {
                print("Error: \(error)")
                return
            }
            
            // Check for a successful HTTP response
            guard let httpResponse = response as? HTTPURLResponse,
                  (200...299).contains(httpResponse.statusCode) else {
                print("Error: Invalid HTTP response")
                return
            }
            
            // Parse the JSON data into an array of CVE structs
            guard let data = data else {
                print("Error: No data received")
                return
            }
            do {
                let decoder = JSONDecoder()
                let dateFormatter = DateFormatter()
                dateFormatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'"
                decoder.dateDecodingStrategy = .formatted(dateFormatter)
                let cveArray = try decoder.decode([CVE].self, from: data)
                // Call the completion handler with the array of CVEs
                completion(cveArray)
            } catch {
                print("Error decoding JSON: \(error)")
            }
        }
        
        // Start the data task
        task.resume()
    }
}

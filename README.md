# CVEchecker Documentation

## CVE Struct

The `CVE` struct represents a Common Vulnerabilities and Exposures (CVE) entry. It contains information about a specific security vulnerability.

### Properties

- `CVE`: A string representing the CVE identifier.
- `severity`: A string representing the severity level of the vulnerability.
- `advisories`: An array of strings containing advisory information related to the vulnerability.
- `bugzilla`: A string representing the Bugzilla identifier associated with the vulnerability.
- `bugzilla_description`: A string describing the Bugzilla issue.
- `cvss_score`: A string representing the CVSS (Common Vulnerability Scoring System) score of the vulnerability.
- `cvss_scoring_vector`: A string representing the CVSS scoring vector.
- `CWE`: A string representing the Common Weakness Enumeration (CWE) identifier.
- `affected_packages`: An array of strings containing the names of affected packages.
- `resource_url`: A string representing the URL of the resource related to the vulnerability.
- `cvss3_scoring_vector`: A string representing the CVSS3 scoring vector.
- `cvss3_score`: A string representing the CVSS3 score of the vulnerability.
- `publicDate`: A string representing the public date of the vulnerability.

### Initialization

The `CVE` struct can be initialized using a decoder by conforming to the `Codable` protocol. The `init(from decoder: Decoder)` initializer decodes the properties using the provided coding keys.

## CVEchecker Struct

The `CVEchecker` struct is responsible for checking CVEs (Common Vulnerabilities and Exposures) using the Red Hat Security Data API.

### Methods

- `getCVEs(package:after:completion:)`: This method retrieves CVE information for a specific package and after a specified date. It makes a request to the Red Hat Security Data API and returns an array of `CVE` objects or an error through the completion closure.

#### Parameters

- `package`: A string representing the package name to check for CVEs.
- `after`: A string representing the date after which to retrieve CVEs.
- `completion`: A closure that receives an optional array of `CVE` objects and an optional error. The closure is called when the API request is complete.

#### Usage

To use the `CVEchecker` struct, create an instance and call the `getCVEs` method, providing the package name and the date. Handle the response in the completion closure, where you can access the retrieved CVEs or handle any errors that occurred during the API request.

```swift
let checker = CVEchecker()
checker.getCVEs(package: "example-package", after: "2023-01-01") { cves, error in
    if let error = error {
        // Handle the error
        print("Error: \(error)")
    } else if let cves = cves {
        // Access the retrieved CVEs
        for cve in cves {
            print("CVE: \(cve.CVE ?? "")")
            // Access other properties of the CVE object
        }
    }
}


https://access.redhat.com/documentation/en-us/red_hat_security_data_api/1.0/html/red_hat_security_data_api/index

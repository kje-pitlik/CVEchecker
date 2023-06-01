import XCTest
import Alamofire

@testable import CVEchecker // Replace 'YourModuleName' with the actual name of your module

class CVEcheckerTests: XCTestCase {
    func testGetCVEs() {
        let expectation = XCTestExpectation(description: "Fetch CVEs")

        let checker = CVEchecker()
        let product = "iphoneos" // Replace 'YourProduct' with the product you want to test
        let after = "2000-01-01" // Replace '2022-01-01' with the desired date

        checker.getCVEs(product: product, after: after) { cves, error in
            XCTAssertNil(error, "Error occurred: \(error?.localizedDescription ?? "")")
            XCTAssertNotNil(cves, "CVEs not retrieved")
            
            if let cves = cves {
                           for cve in cves {
                               print("CVE: \(cve.CVE ?? "")")
                               print("Severity: \(cve.severity ?? "")")
                               // Print other desired properties
                               print("----------------------")
                           }
                       } else {
                           XCTFail("CVEs not retrieved")
                       }
            expectation.fulfill()
        }

        wait(for: [expectation], timeout: 10000.0) // Adjust the timeout value as needed
    }
}

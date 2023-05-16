import XCTest
import Alamofire

@testable import CVEchecker // replace with the name of your project

class CVEcheckerTests: XCTestCase {
    
    func testGetCVEs() {
        let cveChecker = CVEchecker()
        let package = "ios"
        let after = "2019-01-01"
        
        let expectation = XCTestExpectation(description: "Get CVEs")
        
        cveChecker.getCVEs(package: package, after: after) { (cves, error) in
            XCTAssertNotNil(cves, "CVEs should not be nil")
            XCTAssertNil(error, "Error should be nil")
            
            if let cves = cves {
                XCTAssertGreaterThan(cves.count, 0, "There should be at least one CVE")
                for cve in cves {
                    XCTAssertNotNil(cve.CVE, "CVE should not be nil")
                    XCTAssertNotNil(cve.severity, "Severity should not be nil")
                    XCTAssertNotNil(cve.public_date, "Public date should not be nil")
                    XCTAssertNotNil(cve.advisories, "Advisories should not be nil")
                    XCTAssertNotNil(cve.bugzilla, "Bugzilla should not be nil")
                    XCTAssertNotNil(cve.bugzilla_description, "Bugzilla description should not be nil")
                    XCTAssertNotNil(cve.affected_packages, "Affected packages should not be nil")
                    XCTAssertNotNil(cve.resource_url, "Resource URL should not be nil")
                    XCTAssertNotNil(cve.cvss3_scoring_vector, "CVSS3 scoring vector should not be nil")
                    XCTAssertNotNil(cve.cvss3_score, "CVSS3 score should not be nil")
                }
            }
            
            expectation.fulfill()
        }
        
        wait(for: [expectation], timeout: 10.0)
    }
}

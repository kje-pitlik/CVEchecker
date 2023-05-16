import XCTest
@testable import CVEchecker
class CVEcheckerTests: XCTestCase {

    func testGetCVEs() {
        let cveChecker = CVEchecker()
        
        let expectation = self.expectation(description: "Fetching CVEs")
        
        cveChecker.getCVEs(package: "ios", after: "2019-01-01") { (cves, error) in
            XCTAssertNil(error)
            XCTAssertNotNil(cves)
            
            if let cves = cves {
                XCTAssertTrue(cves.count > 0)
                
                for cve in cves {
                    XCTAssertNotNil(cve.id)
                    XCTAssertNotNil(cve.cvssScore)
                    XCTAssertNotNil(cve.summary)
                }
            }
            
            expectation.fulfill()
        }
        
        waitForExpectations(timeout: 10, handler: nil)
    }

}

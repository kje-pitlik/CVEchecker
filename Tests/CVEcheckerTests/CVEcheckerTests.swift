import XCTest
@testable import CVEchecker
class CVEcheckerTests: XCTestCase {

    func testGetCVEs() {
        let expectation = self.expectation(description: "GET request should return CVE data")
        CVEchecker().getCVEs(package: "ios", after: "2000-01-01") { cves, error in
            XCTAssertNil(error, "Error should be nil")
            XCTAssertNotNil(cves, "CVE data should not be nil")
            expectation.fulfill()
        }
        
        waitForExpectations(timeout: 5, handler: nil)
    }
}

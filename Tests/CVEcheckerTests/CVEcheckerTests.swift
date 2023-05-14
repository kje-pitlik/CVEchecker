import XCTest
@testable import CVEchecker
class CVEcheckerTests: XCTestCase {

    func testGetCVEs() {
        let expectation = self.expectation(description: "GET request should return CVE data")
        CVEchecker().getCVEs(package: "ios", after: "2000-01-01") { cves, error in
            expectation.fulfill()
        }
        
        waitForExpectations(timeout: 5, handler: nil)
    }
}

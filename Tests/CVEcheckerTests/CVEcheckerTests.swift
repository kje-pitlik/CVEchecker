import XCTest
@testable import CVEchecker
class CVEcheckerTests: XCTestCase {

    func testGetCVEs() {
        let expectation = self.expectation(description: "GET request should return CVE data")
        CVEchecker().getCVEs(package: "ios", after: "2019-01-01") { cves, error in
            XCTAssertNotNil(cves, "Expected to receive CVE data")
            XCTAssertNil(error, "Expected no error to occur")
            XCTAssertEqual(cves!.count, 6, "Expected to receive 6 CVEs")
            expectation.fulfill()
        }
        
        waitForExpectations(timeout: 5, handler: nil)
    }

}

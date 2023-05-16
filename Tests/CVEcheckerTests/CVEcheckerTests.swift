import XCTest
import Alamofire

@testable import CVEchecker // replace with the name of your project

class CVEcheckerTests: XCTestCase {
    
    func testGetCVEs() {
        let expectation = self.expectation(description: "API call successful")
        let package = "openssl"
        let after = "2021-01-01T00:00:00Z"
        CVEchecker().getCVEs(package: package, after: after) { cveArray in
            // Assert that the returned array of CVEs is not empty
            XCTAssertFalse(cveArray.isEmpty)
            expectation.fulfill()
        }
        
        waitForExpectations(timeout: 5, handler: nil)
    }
}

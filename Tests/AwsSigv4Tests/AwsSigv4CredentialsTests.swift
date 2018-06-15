import XCTest
@testable import AwsSigv4

final class AwsSigv4CredentialsTests: XCTestCase {
    func testInit() {
        let credentials = AwsSigv4Credentials("", "", "TEST")
        XCTAssertEqual(credentials.sessionToken, "TEST")
    }

    static var allTests = [
        ("testInit", testInit),
    ]
}

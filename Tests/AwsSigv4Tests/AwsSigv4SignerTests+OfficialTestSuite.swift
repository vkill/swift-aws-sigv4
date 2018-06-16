import XCTest
@testable import AwsSigv4
import class Foundation.FileManager

extension AwsSigv4SignerTests {

    struct OfficialTestSuite {
        let credentialScope: String
        let secretKey: String
        let cases: [`case`]

        struct `case` {
            let name: String

            let req: String
            let creq: String
            let sts: String
            let authz: String
            let sreq: String
        }
    }

    func testOfficialTestSuite() throws {
        // TODO
        let suites = makeOfficialTestSuite()
    }

    func makeOfficialTestSuite() -> OfficialTestSuite {
        let dir = AwsSigv4TestsHelper.workdir() + "offcial_test_suite/"

        let credentialScope = ""
        let secretKey = ""
        var cases: [OfficialTestSuite.`case`] = []

        return OfficialTestSuite(credentialScope: credentialScope, secretKey: secretKey, cases: cases)
    }
}

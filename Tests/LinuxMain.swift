import XCTest

import AwsSigv4Tests

var tests = [XCTestCaseEntry]()
tests += AwsSigv4Tests.allTests()
XCTMain(tests)
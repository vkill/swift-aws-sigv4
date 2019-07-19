// swift-tools-version:5.0

import PackageDescription

let package = Package(
    name: "AwsSigv4",
    products: [
        .library(name: "AwsSigv4", targets: ["AwsSigv4"])
    ],
    dependencies: [
    ],
    targets: [
        .target(name: "AwsSigv4", dependencies: []),
        .testTarget(name: "AwsSigv4Tests", dependencies: ["AwsSigv4"])
    ]
)

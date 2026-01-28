// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "PQContainerKit",
    platforms: [
        .iOS(.v26)
    ],
    products: [
        .library(
            name: "PQContainerKit",
            targets: ["PQContainerKit"]
        ),
    ],
    targets: [
        .target(
            name: "PQContainerKit"
        ),
        .testTarget(
            name: "PQContainerKitTests",
            dependencies: ["PQContainerKit"]
        ),
    ]
)

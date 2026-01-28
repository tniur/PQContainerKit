// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "PQContainerKit",
    platforms: [
        .iOS(.v26),
        .macOS(.v12)
    ],
    products: [
        .library(name: "PQContainerKit", targets: ["PQContainerKit"])
    ],
    dependencies: [
        .package(url: "https://github.com/nicklockwood/SwiftFormat", from: "0.59.0"),
        .package(url: "https://github.com/SimplyDanny/SwiftLintPlugins", from: "0.63.2")
    ],
    targets: [
        .target(
            name: "PQContainerKit",
            plugins: [
                .plugin(name: "SwiftLintBuildToolPlugin", package: "SwiftLintPlugins")
            ]
        ),
        .testTarget(
            name: "PQContainerKitTests",
            dependencies: ["PQContainerKit"]
        ),
    ]
)

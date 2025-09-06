// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "BetterAuthSwift",
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15)
    ],
    products: [
        .library(
            name: "BetterAuthSwift",
            targets: ["BetterAuthSwift"]
        ),
    ],
    dependencies: [
    ],
    targets: [
        .target(
            name: "BetterAuthSwift",
            dependencies: []
        ),
        .testTarget(
            name: "BetterAuthSwiftTests",
            dependencies: ["BetterAuthSwift"]
        ),
    ]
)


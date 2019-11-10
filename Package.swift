// swift-tools-version:5.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "FirebaseJWTMiddleware",
    products: [
        .library(name: "FirebaseJWTMiddleware", targets: ["FirebaseJWTMiddleware"]),
    ],
    dependencies: [
        .package(url: "https://github.com/vapor/vapor.git", from: "4.0.0-beta.1"),
        .package(url: "https://github.com/vapor/jwt-kit.git", from: "4.0.0-alpha.1.3"),
    ],
    targets: [
        .target(name: "FirebaseJWTMiddleware", dependencies: ["Vapor", "JWTKit"]),
        .testTarget(name: "FirebaseJWTMiddlewareTests", dependencies: ["FirebaseJWTMiddleware"]),
    ]
)

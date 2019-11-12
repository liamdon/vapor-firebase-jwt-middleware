import XCTest
import Vapor
import NIOSSL
@testable import FirebaseJWTMiddleware

final class FirebaseJWTMiddlewareTests: XCTestCase {
    func testExample() throws {

        // Paste your own token here
        let token = """
eyJhbGciOiJSUzI1NiIsImtpZCI6IjI1MDgxMWNkYzYwOWQ5MGY5ODE1MTE5MWIyYmM5YmQwY2ViOWMwMDQiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL3NlY3VyZXRva2VuLmdvb2dsZS5jb20vZmlyZXRvZG8tZTk3YTciLCJhdWQiOiJmaXJldG9kby1lOTdhNyIsImF1dGhfdGltZSI6MTU3MzUyMzMyNSwidXNlcl9pZCI6IkdvOTlqejROZE9ka0wxaGgxNHRDdVBQUzhKQjMiLCJzdWIiOiJHbzk5ano0TmRPZGtMMWhoMTR0Q3VQUFM4SkIzIiwiaWF0IjoxNTczNTIzMzI1LCJleHAiOjE1NzM1MjY5MjUsImZpcmViYXNlIjp7ImlkZW50aXRpZXMiOnt9LCJzaWduX2luX3Byb3ZpZGVyIjoiY3VzdG9tIn19.hFlYzFWJuC5d0wUdbGhM5nPyPF9FuzuS6m66TW3XZLdDrRknjM-1iBEC9TMEZlqKyqz0-k-BjfjgGPJeDYXoVRNPqqVRlhJThDWmIC2Z5hrziyU-kqwIiMqsvQsn3Sx4rCRYeblERKtY4bwLcmaAsSwHcSfYeQUzpgVNs0N_WsU9Qb15SubqYKcD4l9TL4qWmcne3fOptdxxDq7PBnvVi1FoUdcf3FLTSqbAOiTr3cuORXwsgwwJtK5iNsJ3ZczVHwgA-r73U_6bvEpDiHyaFF5keERFy0NHhkJIEjy_6I8-DlOOn5o9idDENugmKhRMom0aoaWGDWz8puj5TRxiyA
"""

        let app = Application()
        defer { app.shutdown() }

        FirebaseJWTMiddlewareConfig.configure(issuer: "https://securetoken.google.com/firetodo-e97a7")

        app.register(HTTPClient.Configuration.self) { app in
            return .init(certificateVerification: .none, ignoreUncleanSSLShutdown: true)
        }

        try app.boot()

        let request = Request(application: app, on: app.make())
        _ = try TokenVerifier.verify(token, request: request).wait()

        // Check return from cache
        _ = try TokenVerifier.verify(token, request: request).wait()

    }

    static var allTests = [
        ("testExample", testExample),
    ]
}

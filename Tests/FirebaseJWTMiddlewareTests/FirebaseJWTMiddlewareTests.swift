import XCTest
import Vapor
import NIOSSL
@testable import FirebaseJWTMiddleware

final class FirebaseJWTMiddlewareTests: XCTestCase {
    func testExample() throws {

        // Paste your own token here
        let token = """
eyJhbGciOiJSUzI1NiIsImtpZCI6IjI1MDgxMWNkYzYwOWQ5MGY5ODE1MTE5MWIyYmM5YmQwY2ViOWMwMDQiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL3NlY3VyZXRva2VuLmdvb2dsZS5jb20vZmlyZXRvZG8tZTk3YTciLCJhdWQiOiJmaXJldG9kby1lOTdhNyIsImF1dGhfdGltZSI6MTU3MzQ0MTUwMCwidXNlcl9pZCI6IkdvOTlqejROZE9ka0wxaGgxNHRDdVBQUzhKQjMiLCJzdWIiOiJHbzk5ano0TmRPZGtMMWhoMTR0Q3VQUFM4SkIzIiwiaWF0IjoxNTczNDQxNTAwLCJleHAiOjE1NzM0NDUxMDAsImZpcmViYXNlIjp7ImlkZW50aXRpZXMiOnt9LCJzaWduX2luX3Byb3ZpZGVyIjoiY3VzdG9tIn19.n1W5Nu5PJKEeElJ0Hw2hOG8FVuqZCTmilex-9tY-A4QqoGk2STvemxNXluo5Iedcyp0tNYzyhGArJOOJQrSShvkgPqfK5LKuT37Hlm9a4baZJ0c_ovQgHH_DLPJJ2nVLGlG-jTDFGU283mzXKg7w8s2ntt2HSgvKrfCbJ6V0TqkSBfv8rj3fgj1R3BmRBRA4Oa4mh7ZHtbhVy2J5OSf1jGLzlDh_bYIEIPlllpsGBnIJ6x3ABK99TerSxDmzkys5ndDH1kJ3zLcs2e6m-u6_Sn9MStseJOmhjovYMZCUQgv3yIrcN4PoLgXDIpuSAwoWEYrTS_FITCALbgTpKNLJxQ
"""

        let app = Application()
        defer { app.shutdown() }

        FirebaseJWTMiddlewareConfig.configure(issuer: "https://securetoken.google.com/firetodo-e97a7")

        app.register(HTTPClient.Configuration.self) { app in
            return .init(certificateVerification: .none, ignoreUncleanSSLShutdown: true)
        }

        try app.boot()

        let result = try TokenVerifier.verify(token, app.client).wait()
        print(result)

    }

    static var allTests = [
        ("testExample", testExample),
    ]
}

import XCTest
import Vapor
import NIOSSL
@testable import FirebaseJWTMiddleware

final class FirebaseJWTMiddlewareTests: XCTestCase {
    func testExample() throws {

        // Paste your own token here
        let token = """
eyJhbGciOiJSUzI1NiIsImtpZCI6IjI1MDgxMWNkYzYwOWQ5MGY5ODE1MTE5MWIyYmM5YmQwY2ViOWMwMDQiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL3NlY3VyZXRva2VuLmdvb2dsZS5jb20vZmlyZXRvZG8tZTk3YTciLCJhdWQiOiJmaXJldG9kby1lOTdhNyIsImF1dGhfdGltZSI6MTU3MzQzMDUxMSwidXNlcl9pZCI6IkdvOTlqejROZE9ka0wxaGgxNHRDdVBQUzhKQjMiLCJzdWIiOiJHbzk5ano0TmRPZGtMMWhoMTR0Q3VQUFM4SkIzIiwiaWF0IjoxNTczNDMwNTExLCJleHAiOjE1NzM0MzQxMTEsImZpcmViYXNlIjp7ImlkZW50aXRpZXMiOnt9LCJzaWduX2luX3Byb3ZpZGVyIjoiY3VzdG9tIn19.X43xRFG1dQJjwalmfcW9_eDERcCFmfonc-PS_uqe4j-xVIB5s9vpmMbarrB0a0p_rh-wypMy_A7PwVcT4DprWU8pSQpTCeme7KSqxi8n03vkj_XH2xJ-7K__3wdaqRXWUVHkRrsZTEMrevkAlRY0v-AFd1ZZzre6kcVljQUHeiiSekY4kLDEkcnMm07RvQyS7yhan063DEIWqVCM97KFVQa6ITHQj-MpR5dw0iWVRZ4Jj-78MVDUsewC7G90uMXv4nShiZdE28bIrNj1pqWYVmsN43mUy0dykqYl20WapuMQ6-1BSnBUhmXfpHghb7sirMcSiEaSM1lzl8TjDVrcFA
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

import XCTest
import Vapor
import NIOSSL
@testable import FirebaseJWTMiddleware

final class FirebaseJWTMiddlewareTests: XCTestCase {
    func testExample() throws {
        let token = """
eyJhbGciOiJSUzI1NiIsImtpZCI6IjI1MDgxMWNkYzYwOWQ5MGY5ODE1MTE5MWIyYmM5YmQwY2ViOWMwMDQiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL3NlY3VyZXRva2VuLmdvb2dsZS5jb20vZmlyZXRvZG8tZTk3YTciLCJhdWQiOiJmaXJldG9kby1lOTdhNyIsImF1dGhfdGltZSI6MTU3MzQxODc5MiwidXNlcl9pZCI6IkdvOTlqejROZE9ka0wxaGgxNHRDdVBQUzhKQjMiLCJzdWIiOiJHbzk5ano0TmRPZGtMMWhoMTR0Q3VQUFM4SkIzIiwiaWF0IjoxNTczNDE4NzkyLCJleHAiOjE1NzM0MjIzOTIsImZpcmViYXNlIjp7ImlkZW50aXRpZXMiOnt9LCJzaWduX2luX3Byb3ZpZGVyIjoiY3VzdG9tIn19.SbY_vOdt9ft0ii4EOhiC7RYt_92R-rC3W-sfxcUewnHHIDO7SvlG_4MohGJyiKsXdQmwySpxyet8Oywtvxzb853m9QJKeqVtj-WZyfpLVjRaPWKGEsnB9q3eMGDwLFD6Vdyu1R_P_G_CtSAaX3AWn9y4Zg6euUSCWRYmepIBKpYhiGTsHv7TsYv9ms9RpqiC7v5iDHk0zFn4vXwLjEsQY4hZbtqMS-8WQ7A4xz2JIlvacSk1qodYOl_Pg5JfoawwQd0PcJkyX7rLdDgzWnetma5Huk-oTDCFvtDxpKXC3QfKFYe6D5C3Q0zHT3wGBIFL1PK3LuUO7ynYxNbS15ei0A
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

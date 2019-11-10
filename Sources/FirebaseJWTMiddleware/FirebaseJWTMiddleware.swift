import Vapor
import JWTKit

open class FirebaseJWTMiddleware: Middleware {

    public init() {}
    
    public func respond(to request: Request, chainingTo next: Responder) -> EventLoopFuture<Response> {
        if let token = request.headers[.authorization].first {
            do {
                try TokenVerifier.verify(token)
                return next.respond(to: request)
            } catch let error as JWTError {
                return request.eventLoop.makeFailedFuture(Abort(.unauthorized, reason: error.reason))
            } catch let error {
                return request.eventLoop.makeFailedFuture(Abort(.unauthorized, reason: error.localizedDescription))
            }
        } else {
            return request.eventLoop.makeFailedFuture(Abort(.unauthorized, reason: "No Access Token"))
        }
    }
}

enum JWTConfig {
    static let header = JWTHeader(alg: "RS256", typ: "JWT")
    static let expirationTime: TimeInterval = 50
}


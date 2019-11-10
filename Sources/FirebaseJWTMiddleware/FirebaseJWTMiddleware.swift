import Vapor
import JWTKit

open class FirebaseJWTMiddleware: Middleware {

    public init() {}
    
    public func respond(to request: Request, chainingTo next: Responder) -> EventLoopFuture<Response> {

        guard let token = request.headers[.authorization].first else {
            return request.eventLoop.makeFailedFuture(Abort(.unauthorized, reason: "No Access Token"))
        }

        return TokenVerifier.verify(token, request.client)
            .flatMap({ (payload) -> EventLoopFuture<Response> in
                return next.respond(to: request)
            }).flatMapError { (error) -> EventLoopFuture<Response> in
                if let error = error as? JWTError {
                    return request.eventLoop.makeFailedFuture(Abort(.unauthorized, reason: error.reason))
                }
                return request.eventLoop.makeFailedFuture(Abort(.unauthorized))
        }
    }
}

enum JWTConfig {
    static let header = JWTHeader(alg: "RS256", typ: "JWT")
    static let expirationTime: TimeInterval = 50
}


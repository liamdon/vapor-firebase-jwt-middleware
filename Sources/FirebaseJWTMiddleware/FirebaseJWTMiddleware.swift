import Vapor
import JWTKit

let FireBaseJWTPayloadKey = "fireWT"

open class FirebaseJWTMiddleware: Middleware {

    public init() {}
    
    public func respond(to request: Request, chainingTo next: Responder) -> EventLoopFuture<Response> {

        guard let token = request.headers[.authorization].first else {
            return request.eventLoop.makeFailedFuture(Abort(.unauthorized, reason: "No Access Token"))
        }

        return TokenVerifier.verify(token, request.client)
            .flatMap({ (payload) -> EventLoopFuture<Response> in
                request.userInfo[FireBaseJWTPayloadKey] = payload
                return next.respond(to: request)
            }).flatMapError { (error) -> EventLoopFuture<Response> in
                if let error = error as? JWTError {
                    return request.eventLoop.makeFailedFuture(Abort(.unauthorized, reason: error.reason))
                }
                return request.eventLoop.makeFailedFuture(Abort(.unauthorized))
        }
    }
}

extension Request {
    var firebaseJWTPayload: FirebaseJWTPayload? {
        return self.userInfo[FireBaseJWTPayloadKey] as? FirebaseJWTPayload
    }
}

enum JWTConfig {
    static let header = JWTHeader(alg: "RS256", typ: "JWT")
    static let expirationTime: TimeInterval = 50
}


import Vapor
import JWTKit

let FireBaseJWTPayloadKey = "fireWT"

public final class JWTSignersCache {

    private var cachedSigners: JWTSigners?
    private var cacheExpiryEpoch: TimeInterval = Date.timeIntervalSinceReferenceDate

    var lock: Lock

    init() {
        self.lock = .init()
    }

    func get() -> JWTSigners? {
        self.lock.lock()
        defer { self.lock.unlock() }
        if self.cacheExpiryEpoch > Date.timeIntervalSinceReferenceDate {
            return self.cachedSigners
        }
        self.cachedSigners = nil
        return nil
    }

    func set(value: JWTSigners, epiryEpoch: TimeInterval) {
        self.lock.lock()
        defer { self.lock.unlock() }
        self.cachedSigners = value
        self.cacheExpiryEpoch = epiryEpoch
    }
}

open class FirebaseJWTMiddleware: Middleware {

    let signersCache = JWTSignersCache()

    public init() {}
    
    public func respond(to request: Request, chainingTo next: Responder) -> EventLoopFuture<Response> {

        guard let token = request.headers[.authorization].first else {
            return request.eventLoop.makeFailedFuture(Abort(.unauthorized, reason: "No Access Token"))
        }

        return TokenVerifier.verify(token, request: request, cache: self.signersCache)
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
    public var firebaseJWTPayload: FirebaseJWTPayload? {
        return self.userInfo[FireBaseJWTPayloadKey] as? FirebaseJWTPayload
    }
}

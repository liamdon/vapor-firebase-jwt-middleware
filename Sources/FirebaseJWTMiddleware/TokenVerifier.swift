//
//  TokenVerifier.swift
//  Async
//
//  Created by Baris Atamer on 23.08.19.
//

import Vapor
import JWTKit
import OpenCrypto

public class TokenVerifier {

    final class SignersCache {

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

    static let url = URI(stringLiteral: "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com")

    private static var signersCache = SignersCache()
    
    @discardableResult
    public class func verify(_ token: String, request: Request) -> EventLoopFuture<FirebaseJWTPayload> {
        return TokenVerifier.getSigners(request: request).flatMap({ (signers) -> EventLoopFuture<FirebaseJWTPayload> in
            let token = token.removeBearer()
            do {
                let jwt = try JWT<FirebaseJWTPayload>(from: Array(token.utf8), verifiedBy: signers)
                return request.eventLoop.next().makeSucceededFuture(jwt.payload)
            } catch let error {
                return request.eventLoop.makeFailedFuture(error)
            }
        })
    }

    private class func getSigners(request: Request) -> EventLoopFuture<JWTSigners> {

        let promise = request.eventLoop.next().makePromise(of: JWTSigners.self)
        if let signers = signersCache.get() {
            promise.succeed(signers)
            return promise.futureResult
        }

        request.client.get(url).whenComplete { (result) in
            switch result {
            case .failure(let error):
                promise.fail(error)
            case .success(let response):
                guard
                    let responseBody = response.body,
                    let responseString = responseBody.getString(at: 0, length: responseBody.readableBytes) else {
                        promise.fail(JWTError.invalidJWK)
                        return
                }

                do {
                    let signers = JWTSigners()
                    try signers.use(jwksJSON: responseString)

                    // Cache signers by max-age if possible
                    TokenVerifier.cacheSigners(signers, response.headers)

                    promise.succeed(signers)
                } catch let error {
                    promise.fail(error)
                }
            }
        }

        return promise.futureResult

    }

    private class func cacheSigners(_ signers: JWTSigners, _ headers: HTTPHeaders) {
        if
              let cacheControlString = headers.firstValue(name: .cacheControl) {
              let maxAgeMatch = cacheControlString.matches(for: #"max-age=(\d+)"#)

              if let ageString = maxAgeMatch.first?.replacingOccurrences(of: "max-age=", with: "") {
                let expiry = Date.timeIntervalSinceReferenceDate + (Double(ageString) ?? 0.0)
                self.signersCache.set(value: signers, epiryEpoch: expiry)
              }
          }
    }

}

extension String {
    var bytes: [UInt8] {
        return .init(self.utf8)
    }
    
    func removeBearer() -> String {
        return self.replacingOccurrences(of: "Bearer ", with: "")
    }

    func matches(for regex: String) -> [String] {
        do {
            let regex = try NSRegularExpression(pattern: regex)
            let results = regex.matches(in: self,
                                        range: NSRange(self.startIndex..., in: self))

            return results.compactMap {
                guard let range = Range($0.range, in: self) else {
                    return nil
                }
                return String(self[range])
            }
        } catch let error {
            print("invalid regex: \(error.localizedDescription)")
            return []
        }
    }

}

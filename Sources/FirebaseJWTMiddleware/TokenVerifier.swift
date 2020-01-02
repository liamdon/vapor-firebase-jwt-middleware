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
    
    static let url = URI(stringLiteral: "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com")

    @discardableResult
    public class func verify(_ token: String, request: Request, cache: JWTSignersCache) -> EventLoopFuture<FirebaseJWTPayload> {
        return TokenVerifier.getSigners(request: request, cache: cache).flatMap({ (signers) -> EventLoopFuture<FirebaseJWTPayload> in
            let token = token.removeBearer()
            do {
                let payload = try signers.verify(Array(token.utf8), as: FirebaseJWTPayload.self)
                return request.eventLoop.next().makeSucceededFuture(payload)
            } catch let error {
                return request.eventLoop.makeFailedFuture(error)
            }
        })
    }

    private class func getSigners(request: Request, cache: JWTSignersCache) -> EventLoopFuture<JWTSigners> {

        let promise = request.eventLoop.next().makePromise(of: JWTSigners.self)
        if let signers = cache.get() {
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
                    TokenVerifier.cacheSigners(signers, response.headers, cache)

                    promise.succeed(signers)
                } catch let error {
                    promise.fail(error)
                }
            }
        }

        return promise.futureResult

    }

    private class func cacheSigners(_ signers: JWTSigners, _ headers: HTTPHeaders, _ cache: JWTSignersCache) {
        if
              let cacheControlString = headers.firstValue(name: .cacheControl) {
              let maxAgeMatch = cacheControlString.matches(for: #"max-age=(\d+)"#)

              if let ageString = maxAgeMatch.first?.replacingOccurrences(of: "max-age=", with: "") {
                let expiry = Date.timeIntervalSinceReferenceDate + (Double(ageString) ?? 0.0)
                cache.set(value: signers, epiryEpoch: expiry)
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

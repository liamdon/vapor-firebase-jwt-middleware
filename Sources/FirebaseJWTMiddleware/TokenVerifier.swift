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

    private static var cachedSigners: JWTSigners?
    private static var cacheExpiryEpoch: TimeInterval = Date.timeIntervalSinceReferenceDate
    
    @discardableResult
    public class func verify(_ token: String, _ httpClient: Client) -> EventLoopFuture<FirebaseJWTPayload> {
        return TokenVerifier.getSigners(httpClient: httpClient).flatMap({ (signers) -> EventLoopFuture<FirebaseJWTPayload> in
            let promise = httpClient.eventLoopGroup.next().makePromise(of: FirebaseJWTPayload.self)
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    let token = token.removeBearer()
                    let jwt = try JWT<FirebaseJWTPayload>(from: Array(token.utf8), verifiedBy: signers)
                    promise.succeed(jwt.payload)
                } catch let error {
                    promise.fail(error)
                }
            }
            return promise.futureResult
        })
    }

    private class func getSigners(httpClient: Client) -> EventLoopFuture<JWTSigners> {

        let promise = httpClient.eventLoopGroup.next().makePromise(of: JWTSigners.self)
        if let signers = TokenVerifier.cachedSigners, cacheExpiryEpoch > Date.timeIntervalSinceReferenceDate {
            promise.succeed(signers)
            return promise.futureResult
        }

        httpClient.get(url).whenComplete { (result) in
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
                  TokenVerifier.cacheExpiryEpoch = Date.timeIntervalSinceReferenceDate + (Double(ageString) ?? 0.0)
                  TokenVerifier.cachedSigners = signers
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

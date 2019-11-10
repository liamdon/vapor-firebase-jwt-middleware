//
//  TokenVerifier.swift
//  Async
//
//  Created by Baris Atamer on 23.08.19.
//

import JWTKit
import OpenCrypto

public class TokenVerifier {
    
    @discardableResult
    public class func verify(_ token: String) throws -> FirebaseJWTPayload {
        let token = token.removeBearer()
        do {
            let jwtSigners = try GoogleJWKFetcher.fetch()
            let jwt = try JWT<FirebaseJWTPayload>(from: Array(token.utf8), verifiedBy: jwtSigners)
            return jwt.payload
        } catch let error as JWTError {
            throw error
        } catch {
            throw JWTError.signatureVerifictionFailed
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
}

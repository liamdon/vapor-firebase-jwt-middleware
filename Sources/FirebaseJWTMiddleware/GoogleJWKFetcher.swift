//
//  GoogleJWKFetcher.swift
//  FirebaseJWTMiddleware
//
//  Created by Baris Atamer on 23.08.19.
//

import Foundation
import JWTKit

class GoogleJWKFetcher {
    
    struct Constants {
        static let url = "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com"
    }
    
    class func fetch() throws -> JWTSigners {
        let response = try String(
            contentsOf: URL(string: Constants.url)!,
            encoding: .utf8
        )
        let signers = JWTSigners()
        try signers.use(jwksJSON: response)
        return signers
    }
}

//
//  Response.swift
//  PasskeySample
//
//  Created by Yuya Oka on 2024/01/07.
//

import Foundation

struct Response {}

extension Response {
    struct RegistrationBegin: Decodable {
        let userID: String
        let challenge: Data
        let excludedCredentials: [Data]

        // MARK: - CodingKeys
        private enum CodingKeys: String, CodingKey {
            case userID = "user_id"
            case challenge
            case excludedCredentials = "excluded_credentials"
        }
    }
}

extension Response {
    struct AuthenticateBegin: Decodable {
        let challenge: Data
        let allowCredentials: [Data]

        // MARK: - CodingKeys
        private enum CodingKeys: String, CodingKey {
            case challenge
            case allowCredentials = "allow_credentials"
        }
    }
}

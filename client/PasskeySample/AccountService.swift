//
//  AccountService.swift
//  PasskeySample
//
//  Created by Yuya Oka on 2024/01/09.
//

import AuthenticationServices
import Foundation

protocol AccountServiceDelegate: AnyObject {
    func accountServiceShouldPresentationAnchor() -> ASPresentationAnchor
    func accountServiceSuccessSignUp()
    func accountServiceSuccessSignIn()
}

final class AccountService: NSObject {
    weak var delegate: AccountServiceDelegate?

    private static let relyingPartyIdentifier = "b3ca-240d-1a-46d-7600-f405-d424-3f10-38d4.ngrok-free.app"
    private static let urlSession = URLSession.shared

    private var userID: String?

    func signUp(email: String) async throws {
        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: Self.relyingPartyIdentifier)

        let response = try await requestRegistrationBegin(email: email)

        let registrationRequest = provider.createCredentialRegistrationRequest(
            challenge: response.challenge,
            name: email,
            userID: Data(response.userID.utf8)
        )
        registrationRequest.displayName = email
        registrationRequest.userVerificationPreference = .preferred

//        registrationRequest.excludedCredentials = response.excludedCredentials.map {
//            ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: $0)
//        }

        let controller = ASAuthorizationController(authorizationRequests: [registrationRequest])
        controller.delegate = self
        controller.presentationContextProvider = self
        controller.performRequests()
    }

    func signIn(email: String) async throws {
        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: Self.relyingPartyIdentifier)

        let response = try await requestAuthenticateBegin(email: email)

        let assertionRequest = provider.createCredentialAssertionRequest(challenge: response.challenge)
        assertionRequest.allowedCredentials = response.allowCredentials.map {
            ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: $0)
        }

        let controller = ASAuthorizationController(authorizationRequests: [assertionRequest])
        controller.delegate = self
        controller.presentationContextProvider = self
        controller.performRequests()
    }
}

// MARK: - Private method
private extension AccountService {
    func requestRegistrationBegin(email: String) async throws -> Response.RegistrationBegin {
        let urlRequest: URLRequest = {
            let url = URL(string: "https://\(Self.relyingPartyIdentifier)/registration-begin")!
            var urlRequest = URLRequest(url: url)
            urlRequest.httpMethod = "POST"
            let jsonObject = [
                "email": email
            ]
            urlRequest.httpBody = try? JSONSerialization.data(withJSONObject: jsonObject)
            return urlRequest
        }()
        let response = try await sendURLRequest(urlRequest, responseType: Response.RegistrationBegin.self)

        self.userID = response.userID

        return response
    }

    func requestAuthenticateBegin(email: String) async throws -> Response.AuthenticateBegin {
        let urlRequest: URLRequest = {
            let url = URL(string: "https://\(Self.relyingPartyIdentifier)/authenticate-begin")!
            var urlRequest = URLRequest(url: url)
            urlRequest.httpMethod = "POST"
            let jsonObject = [
                "email": email
            ]
            urlRequest.httpBody = try? JSONSerialization.data(withJSONObject: jsonObject)
            return urlRequest
        }()
        let response = try await sendURLRequest(urlRequest, responseType: Response.AuthenticateBegin.self)

        return response
    }

    func sendPublicKeyCredentialRegistration(
        for userID: String,
        credential: ASAuthorizationPlatformPublicKeyCredentialRegistration
    ) async throws {
        let urlRequest: URLRequest = {
            let url = URL(string: "https://\(Self.relyingPartyIdentifier)/registration-complete")!
            var urlRequest = URLRequest(url: url)
            urlRequest.httpMethod = "POST"

            let jsonObject: [String: Any] = [
                "user_id": userID,
                "credential_id": credential.credentialID.base64EncodedString(),
                "attestation_object": credential.rawAttestationObject?.base64EncodedString(),
                "client_data_json": credential.rawClientDataJSON.base64EncodedString()
            ].compactMapValues { $0 }
            urlRequest.httpBody = try? JSONSerialization.data(withJSONObject: jsonObject)
            return urlRequest
        }()
        try await sendURLRequest(urlRequest)
    }

    func sendPublicKeyCredentialAssertion(credential: ASAuthorizationPlatformPublicKeyCredentialAssertion) async throws {
        let urlRequest: URLRequest = {
            let url = URL(string: "https://\(Self.relyingPartyIdentifier)/authenticate-complete")!
            var urlRequest = URLRequest(url: url)
            urlRequest.httpMethod = "POST"

            let jsonObject = [
                "user_id": credential.userID.base64EncodedString(),
                "credential_id": credential.credentialID.base64EncodedString(),
                "authenticator_data": credential.rawAuthenticatorData.base64EncodedString(),
                "signature": credential.signature.base64EncodedString(),
                "client_data_json": credential.rawClientDataJSON.base64EncodedString()
            ]
            urlRequest.httpBody = try? JSONSerialization.data(withJSONObject: jsonObject)
            return urlRequest
        }()
        try await sendURLRequest(urlRequest)
    }

    func sendURLRequest<T: Decodable>(_ urlRequest: URLRequest, responseType: T.Type) async throws -> T {
        let (data, urlResponse) = try await Self.urlSession.data(for: urlRequest)
        guard let urlResponse = urlResponse as? HTTPURLResponse else { fatalError() }
        guard urlResponse.statusCode == 200 else {
            print("Status code: \(urlResponse.statusCode)")
            throw Error.invalidAPIRequest
        }

        do {
            let response = try JSONDecoder().decode(T.self, from: data)
            return response
        } catch {
            print(error)
            throw error
        }
    }

    func sendURLRequest(_ urlRequest: URLRequest) async throws {
        let (data, urlResponse) = try await Self.urlSession.data(for: urlRequest)
        guard let urlResponse = urlResponse as? HTTPURLResponse else { fatalError() }
        guard urlResponse.statusCode == 200 else {
            print("Status code: \(urlResponse.statusCode)")
            throw Error.invalidAPIRequest
        }
    }
}

// MARK: - ASAuthorizationControllerDelegate
extension AccountService: ASAuthorizationControllerDelegate {
    func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        switch authorization.credential {
        case let credential as ASAuthorizationPlatformPublicKeyCredentialRegistration:
            print("A new passkey was registered")
            guard let userID else { return }
            Task {
                try await sendPublicKeyCredentialRegistration(for: userID, credential: credential)
                self.userID = nil
                delegate?.accountServiceSuccessSignUp()
            }
        case let credential as ASAuthorizationPlatformPublicKeyCredentialAssertion:
            print("A passkey was used to sign in")
            Task {
                try await sendPublicKeyCredentialAssertion(credential: credential)
                delegate?.accountServiceSuccessSignIn()
            }
        default:
            break
        }
    }
}

// MARK: - ASAuthorizationControllerPresentationContextProviding
extension AccountService: ASAuthorizationControllerPresentationContextProviding {
    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        guard let delegate else { fatalError("Should set delegate property") }
        return delegate.accountServiceShouldPresentationAnchor()
    }
}

// MARK: - Error
extension AccountService {
    enum Error: Swift.Error {
        case invalidAPIRequest
    }
}

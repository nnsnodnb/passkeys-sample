//
//  ViewController.swift
//  PasskeySample
//
//  Created by Yuya Oka on 2024/01/07.
//

import AuthenticationServices
import UIKit

final class ViewController: UIViewController {
    private static let relyingPartyIdentifier = "b3ca-240d-1a-46d-7600-f405-d424-3f10-38d4.ngrok-free.app"
    private static let urlSession = URLSession.shared

    private var userID: String?

    @IBOutlet private var textField: UITextField!
    @IBOutlet private var signUpButton: UIButton! {
        didSet {
            signUpButton.layer.borderColor = UIColor.tintColor.cgColor
            signUpButton.layer.borderWidth = 1
            signUpButton.layer.cornerRadius = 20
            signUpButton.layer.masksToBounds = true
        }
    }
    @IBOutlet private var signInButton: UIButton! {
        didSet {
            signInButton.layer.borderColor = UIColor.tintColor.cgColor
            signInButton.layer.borderWidth = 1
            signInButton.layer.cornerRadius = 20
            signInButton.layer.masksToBounds = true
        }
    }

    override func viewDidLoad() {
        super.viewDidLoad()
    }

    @IBAction private func onTapSignUpButton(_ sender: Any) {
        guard let text = textField.text, !text.isEmpty else { return }
        textField.resignFirstResponder()
        Task {
            try await startSignUp(email: text)
        }
    }

    @IBAction private func onTapSignInButton(_ sender: Any) {
        guard let text = textField.text, !text.isEmpty else { return }
        textField.resignFirstResponder()
        Task {
            try await startSignIn(email: text)
        }
    }
}

// MARK: - Private method
private extension ViewController {
    func startSignUp(email: String) async throws {
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

    func startSignIn(email: String) async throws {
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

        let (_, urlResponse) = try await Self.urlSession.data(for: urlRequest)
        guard let urlResponse = urlResponse as? HTTPURLResponse, urlResponse.statusCode == 200 else {
            print("Error: \(urlResponse)")
            return
        }
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

        let (_, urlResponse) = try await Self.urlSession.data(for: urlRequest)
        guard let urlResponse = urlResponse as? HTTPURLResponse, urlResponse.statusCode == 200 else {
            print("Error: \(urlResponse)")
            return
        }
    }

    func showSuccessAlert(title: String) {
        let alert = UIAlertController(title: title, message: nil, preferredStyle: .alert)
        alert.addAction(.init(title: "OK", style: .default))
        present(alert, animated: true)
    }
}

// MARK: - ASAuthorizationControllerDelegate
extension ViewController: ASAuthorizationControllerDelegate {
    func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        switch authorization.credential {
        case let credential as ASAuthorizationPlatformPublicKeyCredentialRegistration:
            print("A new passkey was registered")
            guard let userID else { return }
            Task {
                try await sendPublicKeyCredentialRegistration(for: userID, credential: credential)
                self.userID = nil
                showSuccessAlert(title: "Signed up")
            }
        case let credential as ASAuthorizationPlatformPublicKeyCredentialAssertion:
            print("A passkey was used to sign in")
            Task {
                try await sendPublicKeyCredentialAssertion(credential: credential)
                showSuccessAlert(title: "Signed in")
            }
        default:
            break
        }
    }
}

// MARK: - ASAuthorizationControllerPresentationContextProviding
extension ViewController: ASAuthorizationControllerPresentationContextProviding {
    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        return view.window ?? .init()
    }
}

extension ViewController {
    enum Error: Swift.Error {
        case invalidAPIRequest
    }
}

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

    private let accountService: AccountService = .init()

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
        accountService.delegate = self
    }

    @IBAction private func onTapSignUpButton(_ sender: Any) {
        guard let text = textField.text, !text.isEmpty else { return }
        textField.resignFirstResponder()
        Task {
            try await accountService.signUp(email: text)
        }
    }

    @IBAction private func onTapSignInButton(_ sender: Any) {
        guard let text = textField.text, !text.isEmpty else { return }
        textField.resignFirstResponder()
        Task {
            try await accountService.signIn(email: text)
        }
    }
}

// MARK: - Private method
private extension ViewController {
    func showSuccessAlert(title: String) {
        Task { @MainActor in
            let alert = UIAlertController(title: title, message: nil, preferredStyle: .alert)
            alert.addAction(.init(title: "OK", style: .default))
            present(alert, animated: true)
        }
    }
}

// MARK: - AccountServiceDelegate
extension ViewController: AccountServiceDelegate {
    func accountServiceShouldPresentationAnchor() -> ASPresentationAnchor {
        return view.window ?? .init()
    }

    func accountServiceSuccessSignUp() {
        showSuccessAlert(title: "Signed up")
    }

    func accountServiceSuccessSignIn() {
        showSuccessAlert(title: "Signed in")
    }
}

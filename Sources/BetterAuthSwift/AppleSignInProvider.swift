import Foundation

#if canImport(AuthenticationServices)
import AuthenticationServices
#endif
#if os(iOS)
import UIKit
#endif
#if os(macOS)
import AppKit
#endif

/// Abstraction for providers that can return an access/identity token.
public protocol SignInTokenProvider {
    /// Fetches a provider-specific token to send to the backend.
    func fetchToken() async throws -> String
    /// JSON key under which the token should be sent (e.g., "identityToken", "accessToken").
    var tokenKey: String { get }
}

#if canImport(AuthenticationServices)
/// Sign in with Apple token provider using AuthenticationServices.
public final class AppleSignInTokenProvider: NSObject, SignInTokenProvider {
    private let presentationAnchor: ASPresentationAnchor?
    private var strongDelegate: Delegate?

    public init(presentationAnchor: ASPresentationAnchor? = nil) {
        self.presentationAnchor = presentationAnchor
        super.init()
    }

    /// The JSON key used by the Better Auth backend for Apple identity tokens.
    public var tokenKey: String { "identityToken" }

    @MainActor
    /// Presents the Apple sign-in flow and returns an identity token (JWT).
    public func fetchToken() async throws -> String {
        try await withCheckedThrowingContinuation { continuation in
            let provider = ASAuthorizationAppleIDProvider()
            let request = provider.createRequest()
            request.requestedScopes = [.fullName, .email]
            let controller = ASAuthorizationController(authorizationRequests: [request])
            let delegate = Delegate(continuation: continuation)
            delegate.owner = self
            controller.delegate = delegate
            controller.presentationContextProvider = delegate
            delegate.anchor = presentationAnchor
            self.strongDelegate = delegate
            controller.performRequests()
        }
    }

    @MainActor
    private final class Delegate: NSObject, ASAuthorizationControllerDelegate, ASAuthorizationControllerPresentationContextProviding {
        let continuation: CheckedContinuation<String, Error>
        var anchor: ASPresentationAnchor?
        weak var owner: AppleSignInTokenProvider?

        init(continuation: CheckedContinuation<String, Error>) {
            self.continuation = continuation
            super.init()
        }

        func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
            guard let credential = authorization.credential as? ASAuthorizationAppleIDCredential,
                  let tokenData = credential.identityToken,
                  let token = String(data: tokenData, encoding: .utf8) else {
                continuation.resume(throwing: BetterAuthError.missingToken)
                owner?.strongDelegate = nil
                return
            }
            continuation.resume(returning: token)
            owner?.strongDelegate = nil
        }

        func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
            continuation.resume(throwing: BetterAuthError.appleAuthorization(error))
            owner?.strongDelegate = nil
        }

        func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
            if let anchor = anchor { return anchor }
            #if os(iOS)
            // Attempt best-effort fallback to key window
            return UIApplication.shared.connectedScenes
                .compactMap { $0 as? UIWindowScene }
                .flatMap { $0.windows }
                .first { $0.isKeyWindow } ?? UIWindow()
            #elseif os(macOS)
            return NSApplication.shared.windows.first ?? NSWindow()
            #endif
        }
    }
}
#endif

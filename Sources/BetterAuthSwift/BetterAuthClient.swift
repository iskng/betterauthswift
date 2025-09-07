import Foundation

#if canImport(AuthenticationServices)
import AuthenticationServices
#endif

/// Main entry point for interacting with a Better Auth backend API.
///
/// Provide your backend base URL (e.g., "https://your-server.com").
public final class BetterAuthClient {
    public let baseURL: URL
    private let urlSession: URLSession
    private let decoder: JSONDecoder
    private let encoder: JSONEncoder
    private let tokenStore: TokenStoring
    public enum SignInMode {
        case providerPathSimple                        // POST /signin/{provider} with {identityToken}
        case providerInBodyIdTokenEnvelope            // POST /signin with {provider, idToken: { token, nonce?, accessToken? }}
    }
    private let signInMode: SignInMode

    /// Creates a client with default NotificationCenter-based token notifications.
    /// - Parameters:
    ///   - baseURL: Base server URL (e.g., "https://your-server.com").
    ///   - session: URLSession to use (default .shared).
    ///   - tokenStore: Token storage (default Keychain).
    public init(baseURL: String, session: URLSession = .shared, tokenStore: TokenStoring = KeychainTokenStore(), signInMode: SignInMode = .providerPathSimple) throws {
        guard let url = URL(string: baseURL) else { throw BetterAuthError.invalidURL(baseURL) }
        self.baseURL = url
        self.urlSession = session
        self.decoder = JSONDecoder()
        self.decoder.dateDecodingStrategy = .iso8601
        self.encoder = JSONEncoder()
        self.encoder.dateEncodingStrategy = .iso8601
        self.signInMode = signInMode
        if let notifying = tokenStore as? NotifyingTokenStore {
            self.tokenStore = notifying
        } else {
            self.tokenStore = NotifyingTokenStore(base: tokenStore)
        }
    }

    /// Creates a client with a custom NotificationCenter for token change notifications.
    /// - Parameters:
    ///   - baseURL: Base server URL (e.g., "https://your-server.com").
    ///   - session: URLSession to use (default .shared).
    ///   - tokenStore: Token storage (default Keychain).
    ///   - notificationCenter: NotificationCenter used to emit `.betterAuthTokenDidChange` events.
    public convenience init(baseURL: String, session: URLSession = .shared, tokenStore: TokenStoring = KeychainTokenStore(), notificationCenter: NotificationCenter, signInMode: SignInMode = .providerPathSimple) throws {
        try self.init(baseURL: baseURL, session: session, tokenStore: NotifyingTokenStore(base: tokenStore, center: notificationCenter), signInMode: signInMode)
    }

    /// Returns the currently stored Bearer token, if any.
    public var currentToken: String? { tokenStore.retrieveToken() }

    /// Starts Sign in with Apple and exchanges the identity token with the backend.
    /// - Parameter presentationAnchor: Optional UI anchor for the Apple sign-in sheet.
    /// - Returns: APIResponse containing session and optional user.
    @discardableResult
    public func signInWithApple(presentationAnchor: ASPresentationAnchor? = nil, nonce: String? = nil, accessToken: String? = nil) async throws -> APIResponse<AuthData> {
        #if canImport(AuthenticationServices)
        let provider = AppleSignInTokenProvider(presentationAnchor: presentationAnchor)
        let token = try await provider.fetchToken()
        return try await signInWithApple(identityToken: token, nonce: nonce, accessToken: accessToken)
        #else
        throw BetterAuthError.invalidURL("AuthenticationServices not available on this platform")
        #endif
    }

    /// Sign in with an existing Apple identity token (for testing or custom flows).
    @discardableResult
    public func signInWithApple(identityToken: String, nonce: String? = nil, accessToken: String? = nil) async throws -> APIResponse<AuthData> {
        // Always use provider/idToken envelope format for Apple sign-in
        let envelope = IdTokenEnvelope(token: identityToken, nonce: nonce, accessToken: accessToken)
        let req = ProviderIdTokenSignInRequest(provider: "apple", idToken: envelope)
        return try await postSignInSocial(request: req)
    }

    /// Signs in using a custom provider that returns an access token.
    /// - Parameters:
    ///   - provider: Token provider (e.g., Google) returning an access token.
    ///   - providerName: Provider path segment (e.g., "google").
    /// - Returns: APIResponse containing session and optional user.
    @discardableResult
    public func signIn(with provider: SignInTokenProvider, providerName: String) async throws -> APIResponse<AuthData> {
        let token = try await provider.fetchToken()
        // Always use envelope format for Apple, regardless of signInMode
        if providerName.lowercased() == "apple" {
            return try await signInWithApple(identityToken: token)
        }
        switch signInMode {
        case .providerPathSimple:
            let body = ProviderTokenBody(key: provider.tokenKey, token: token)
            return try await postSignInPath(provider: providerName, body: body)
        case .providerInBodyIdTokenEnvelope:
            // For generic providers under envelope mode, default to sending idToken.token
            let envelope = IdTokenEnvelope(token: token)
            let req = ProviderIdTokenSignInRequest(provider: providerName, idToken: envelope)
            return try await postSignInSocial(request: req)
        }
    }

    /// Fetches the current session from the backend.
    /// - Returns: APIResponse containing session and user if authenticated.
    public func getSession() async throws -> APIResponse<AuthData> {
        let url = baseURL.appendingPathComponent("api/auth/session")
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        attachAuthorization(&request)
        request.timeoutInterval = 30
        let response: APIResponse<AuthData> = try await send(request)
        if let token = response.data?.session.token {
            try tokenStore.storeToken(token)
        }
        return response
    }

    /// Signs out on the server and clears the local token.
    public func signOut() async throws {
        let url = baseURL.appendingPathComponent("api/auth/signout")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        attachAuthorization(&request)
        request.timeoutInterval = 30
        let _: APIResponse<EmptyResponse> = try await send(request)
        try tokenStore.deleteToken()
    }

    /// Refreshes the session (if supported by the backend).
    /// - Parameter refreshToken: Optional refresh token if required by backend.
    /// - Returns: APIResponse containing a new Session.
    public func refreshSession(refreshToken: String? = nil) async throws -> APIResponse<Session> {
        let url = baseURL.appendingPathComponent("api/auth/refresh")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        attachAuthorization(&request)
        request.httpBody = try encoder.encode(RefreshRequest(refreshToken: refreshToken))
        request.timeoutInterval = 30
        let response: APIResponse<Session> = try await send(request)
        if let token = response.data?.token {
            try tokenStore.storeToken(token)
        }
        return response
    }

    // MARK: - Private helpers

    private func attachAuthorization(_ request: inout URLRequest) {
        if let token = tokenStore.retrieveToken() {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
    }

    private func postSignInPath<B: Encodable>(provider: String, body: B) async throws -> APIResponse<AuthData> {
        let url = baseURL.appendingPathComponent("api/auth/signin/\(provider)")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try encoder.encode(body)
        request.timeoutInterval = 30
        let response: APIResponse<AuthData> = try await send(request)
        if let token = response.data?.session.token {
            try tokenStore.storeToken(token)
        }
        return response
    }

    private func postSignInSocial(request body: ProviderIdTokenSignInRequest) async throws -> APIResponse<AuthData> {
        let url = baseURL.appendingPathComponent("api/auth/sign-in/social")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try encoder.encode(body)
        request.timeoutInterval = 30
        let response: APIResponse<AuthData> = try await send(request)
        if let token = response.data?.session.token {
            try tokenStore.storeToken(token)
        }
        return response
    }

    private func send<T: Codable>(_ request: URLRequest) async throws -> APIResponse<T> {
        do {
            let (data, urlResponse) = try await urlSession.data(for: request)
            guard let http = urlResponse as? HTTPURLResponse else {
                throw BetterAuthError.invalidResponse(0, data)
            }

            if !(200...299).contains(http.statusCode) {
                if let apiError = try decodeAPIError(from: data) {
                    throw BetterAuthError.api(apiError)
                } else {
                    throw BetterAuthError.invalidResponse(http.statusCode, data)
                }
            }

            do {
                let decoded = try decoder.decode(APIResponse<T>.self, from: data)
                if let apiError = decoded.error { throw BetterAuthError.api(apiError) }
                return decoded
            } catch let err as BetterAuthError {
                throw err
            } catch {
                throw BetterAuthError.decoding(error)
            }
        } catch let error as BetterAuthError {
            throw error
        } catch {
            throw BetterAuthError.network(error)
        }
    }

    private struct APIErrorEnvelope: Decodable { let error: APIError? }
    private func decodeAPIError(from data: Data) throws -> APIError? {
        // Try wrapper { error: { ... } }
        if let env = try? decoder.decode(APIErrorEnvelope.self, from: data), let err = env.error { return err }
        // Try direct APIError
        if let direct = try? decoder.decode(APIError.self, from: data) { return direct }
        return nil
    }
}

// Encodable dynamic key body for provider tokens
private struct ProviderTokenBody: Encodable {
    let key: String
    let token: String
    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: DynamicCodingKeys.self)
        let codingKey = DynamicCodingKeys(stringValue: key)!
        try container.encode(token, forKey: codingKey)
    }
}

private struct DynamicCodingKeys: CodingKey {
    var stringValue: String
    init?(stringValue: String) { self.stringValue = stringValue }
    var intValue: Int? { nil }
    init?(intValue: Int) { return nil }
}

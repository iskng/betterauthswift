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
    private static let iso8601Full: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()
    private static let iso8601Basic = ISO8601DateFormatter()

    /// Creates a client with default NotificationCenter-based token notifications.
    /// - Parameters:
    ///   - baseURL: Base server URL (e.g., "https://your-server.com").
    ///   - session: URLSession to use (default .shared).
    ///   - tokenStore: Token storage (default Keychain).
    public init(baseURL: String, session: URLSession = .shared, tokenStore: TokenStoring = KeychainTokenStore()) throws {
        guard let url = URL(string: baseURL) else { throw BetterAuthError.invalidURL(baseURL) }
        self.baseURL = url
        self.urlSession = session
        self.decoder = JSONDecoder()
        self.decoder.dateDecodingStrategy = .custom { decoder in
            let container = try decoder.singleValueContainer()
            // Try string ISO8601 (with or without fractional seconds)
            if let str = try? container.decode(String.self) {
                if let d = BetterAuthClient.iso8601Full.date(from: str) { return d }
                if let d = BetterAuthClient.iso8601Basic.date(from: str) { return d }
                if let num = Double(str) {
                    // Interpret numeric string as epoch seconds or milliseconds
                    if num > 1_000_000_000_000 { return Date(timeIntervalSince1970: num / 1000.0) }
                    return Date(timeIntervalSince1970: num)
                }
                throw DecodingError.dataCorruptedError(in: container, debugDescription: "Invalid date string: \(str)")
            }
            // Try numeric timestamps (seconds or milliseconds)
            if let millis = try? container.decode(Int64.self) {
                if millis > 1_000_000_000_000 { return Date(timeIntervalSince1970: TimeInterval(millis) / 1000.0) }
                return Date(timeIntervalSince1970: TimeInterval(millis))
            }
            if let secs = try? container.decode(Double.self) {
                if secs > 1_000_000_000_000 { return Date(timeIntervalSince1970: secs / 1000.0) }
                return Date(timeIntervalSince1970: secs)
            }
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Unsupported date format")
        }
        self.encoder = JSONEncoder()
        self.encoder.dateEncodingStrategy = .iso8601
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
    public convenience init(baseURL: String, session: URLSession = .shared, tokenStore: TokenStoring = KeychainTokenStore(), notificationCenter: NotificationCenter) throws {
        try self.init(baseURL: baseURL, session: session, tokenStore: NotifyingTokenStore(base: tokenStore, center: notificationCenter))
    }

    /// Returns the currently stored Bearer token, if any.
    public var currentToken: String? { tokenStore.retrieveToken() }

    /// Starts Sign in with Apple and exchanges the identity token with the backend.
    /// - Parameter presentationAnchor: Optional UI anchor for the Apple sign-in sheet.
    /// - Returns: APIResponse containing session and optional user.
    @discardableResult
    public func signInWithApple(presentationAnchor: ASPresentationAnchor? = nil, nonce: String? = nil, accessToken: String? = nil, options: SocialSignInOptions? = nil) async throws -> APIResponse<AuthData> {
        #if canImport(AuthenticationServices)
        let provider = AppleSignInTokenProvider(presentationAnchor: presentationAnchor)
        let token = try await provider.fetchToken()
        return try await signInWithApple(identityToken: token, nonce: nonce, accessToken: accessToken, options: options)
        #else
        throw BetterAuthError.invalidURL("AuthenticationServices not available on this platform")
        #endif
    }

    /// Sign in with an existing Apple identity token (for testing or custom flows).
    @discardableResult
    public func signInWithApple(identityToken: String, nonce: String? = nil, accessToken: String? = nil, options: SocialSignInOptions? = nil) async throws -> APIResponse<AuthData> {
        // Try spec-conforming string idToken first, then fallback to envelope if needed
        let reqString = SocialSignInRequest(provider: "apple",
                                            idToken: identityToken,
                                            callbackURL: options?.callbackURL,
                                            newUserCallbackURL: options?.newUserCallbackURL,
                                            errorCallbackURL: options?.errorCallbackURL,
                                            disableRedirect: (options?.disableRedirect ?? true) ? "true" : "false",
                                            scopes: options?.scopes,
                                            requestSignUp: options?.requestSignUp,
                                            loginHint: options?.loginHint)
        do {
            return try await postSignInSocial(request: reqString)
        } catch {
            let envelope = IdTokenEnvelope(token: identityToken, nonce: nonce, accessToken: accessToken)
            let req = SocialSignInEnvelopeRequest(provider: "apple",
                                                  idToken: envelope,
                                                  callbackURL: options?.callbackURL,
                                                  newUserCallbackURL: options?.newUserCallbackURL,
                                                  errorCallbackURL: options?.errorCallbackURL,
                                                  disableRedirect: options?.disableRedirect ?? true,
                                                  scopes: options?.scopes,
                                                  requestSignUp: options?.requestSignUp,
                                                  loginHint: options?.loginHint)
            return try await postSignInSocial(request: req)
        }
    }

    /// Signs in using a custom provider that returns an access token.
    /// - Parameters:
    ///   - provider: Token provider (e.g., Google) returning an access token.
    ///   - providerName: Provider path segment (e.g., "google").
    /// - Returns: APIResponse containing session and optional user.
    @discardableResult
    public func signIn(with provider: SignInTokenProvider, providerName: String) async throws -> APIResponse<AuthData> {
        let token = try await provider.fetchToken()
        let reqString = SocialSignInRequest(provider: providerName, idToken: token, disableRedirect: "true")
        do {
            return try await postSignInSocial(request: reqString)
        } catch {
            let reqEnv = SocialSignInEnvelopeRequest(provider: providerName, idToken: IdTokenEnvelope(token: token), disableRedirect: true)
            return try await postSignInSocial(request: reqEnv)
        }
    }

    /// Fetches the current session from the backend.
    /// - Returns: APIResponse containing session and user if authenticated.
    public func getSession() async throws -> APIResponse<AuthData> {
        let url = baseURL.appendingPathComponent("get-session")
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
        let url = baseURL.appendingPathComponent("sign-out")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        attachAuthorization(&request)
        request.timeoutInterval = 30
        let _: APIResponse<EmptyResponse> = try await send(request)
        try tokenStore.deleteToken()
    }

    /// Refreshes OAuth tokens using a refresh token (Convex/OpenAPI variant).
    public func refreshToken(providerId: String, accountId: String? = nil, userId: String? = nil) async throws -> RefreshTokenResponse {
        let url = baseURL.appendingPathComponent("refresh-token")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try encoder.encode(RefreshTokenRequest(providerId: providerId, accountId: accountId, userId: userId))
        request.timeoutInterval = 30
        let (data, response) = try await urlSession.data(for: request)
        guard let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
            if let apiErr = try? decoder.decode(APIError.self, from: data) { throw BetterAuthError.api(apiErr) }
            throw BetterAuthError.invalidResponse((response as? HTTPURLResponse)?.statusCode ?? 0, data)
        }
        return try decoder.decode(RefreshTokenResponse.self, from: data)
    }

    /// Fetches a Convex JWT associated with the current Better Auth session.
    /// Uses Authorization: Bearer <session token> and returns the JSON `{ token }` value.
    public func getConvexToken() async throws -> String {
        let url = baseURL.appendingPathComponent("convex/token")
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        attachAuthorization(&request)
        request.timeoutInterval = 30
        let (data, response) = try await urlSession.data(for: request)
        guard let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
            if let apiErr = try? decoder.decode(APIError.self, from: data) { throw BetterAuthError.api(apiErr) }
            throw BetterAuthError.invalidResponse((response as? HTTPURLResponse)?.statusCode ?? 0, data)
        }
        struct TokenResp: Decodable { let token: String }
        return try decoder.decode(TokenResp.self, from: data).token
    }

    // MARK: - Private helpers

    private func attachAuthorization(_ request: inout URLRequest) {
        if let token = tokenStore.retrieveToken() {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
    }

    // Removed legacy /signin/{provider} path to align with OpenAPI social endpoint

    private func postSignInSocial(request body: Encodable) async throws -> APIResponse<AuthData> {
        let url = baseURL.appendingPathComponent("sign-in/social")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try encoder.encode(AnyEncodable(body))
        request.timeoutInterval = 30
        do {
            let (data, urlResponse) = try await urlSession.data(for: request)
            guard let http = urlResponse as? HTTPURLResponse else { throw BetterAuthError.invalidResponse(0, data) }
            // First, try normal APIResponse<AuthData>. If completely empty, fall through.
            if let resp = try? decoder.decode(APIResponse<AuthData>.self, from: data) {
                let isCompletelyEmpty = (resp.success == nil && resp.data == nil && resp.error == nil)
                if !isCompletelyEmpty {
                    if let err = resp.error { throw BetterAuthError.api(err) }
                    if let token = resp.data?.session.token { try tokenStore.storeToken(token) }
                    if !(200...299).contains(http.statusCode) { throw BetterAuthError.invalidResponse(http.statusCode, data) }
                    return resp
                }
            }
            // Fallback: social token response { redirect, token }
            if let social = try? decoder.decode(SocialSignInTokenResponse.self, from: data), let token = social.token {
                try tokenStore.storeToken(token)
                let session = Session(token: token, expiresAt: nil, createdAt: nil, updatedAt: nil)
                let auth = AuthData(session: session, user: nil)
                return APIResponse<AuthData>(success: true, data: auth, error: nil)
            }
            // Fallback: capture session token from response header if present (Set-Auth-Token)
            if let headerToken = headerValue(http, name: "Set-Auth-Token"), !headerToken.isEmpty {
                try tokenStore.storeToken(headerToken)
                let session = Session(token: headerToken, expiresAt: nil, createdAt: nil, updatedAt: nil)
                let auth = AuthData(session: session, user: nil)
                return APIResponse<AuthData>(success: true, data: auth, error: nil)
            }
            throw BetterAuthError.decoding(DecodingError.dataCorrupted(.init(codingPath: [], debugDescription: "Unexpected social sign-in response")))
        } catch let e as BetterAuthError {
            throw e
        } catch {
            throw BetterAuthError.network(error)
        }
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

            // Try wrapper response
            if let decoded = try? decoder.decode(APIResponse<T>.self, from: data) {
                let isCompletelyEmpty = (decoded.success == nil && decoded.data == nil && decoded.error == nil)
                if !isCompletelyEmpty {
                    if let apiError = decoded.error { throw BetterAuthError.api(apiError) }
                    return decoded
                }
            }
            // Fallback: direct payload T
            if let direct = try? decoder.decode(T.self, from: data) {
                return APIResponse<T>(success: true, data: direct, error: nil)
            }
            throw BetterAuthError.decoding(DecodingError.dataCorrupted(.init(codingPath: [], debugDescription: "Unable to decode response")))
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

    private func headerValue(_ http: HTTPURLResponse, name: String) -> String? {
        for (k, v) in http.allHeaderFields {
            if let ks = (k as? String)?.lowercased(), ks == name.lowercased() {
                if let s = v as? String { return s }
                return String(describing: v)
            }
        }
        return nil
    }
}

// Encodable dynamic key body for provider tokens
// Removed dynamic token body encoding used by legacy endpoints

// Type-erased Encodable to re-encode unknown Encodable at runtime
private struct AnyEncodable: Encodable {
    private let _encode: (Encoder) throws -> Void
    init(_ encodable: Encodable) { self._encode = encodable.encode }
    func encode(to encoder: Encoder) throws { try _encode(encoder) }
}

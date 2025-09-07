import Foundation

/// Generic API response wrapper for Better Auth endpoints.
/// Supports variations like `{ success, data, error }` and `{ data }`.
public struct APIResponse<T: Codable>: Codable {
    public let success: Bool?
    public let data: T?
    public let error: APIError?

    enum CodingKeys: String, CodingKey {
        case success, data, error
    }

    public init(success: Bool?, data: T?, error: APIError?) {
        self.success = success
        self.data = data
        self.error = error
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let success = try container.decodeIfPresent(Bool.self, forKey: .success)
        let error = try container.decodeIfPresent(APIError.self, forKey: .error)
        if let error = error {
            self.success = false
            self.data = nil
            self.error = error
            return
        }
        // If no error, attempt to decode data (wrapper or direct with missing success)
        let data = try container.decodeIfPresent(T.self, forKey: .data)
        self.success = success ?? (data != nil ? true : nil)
        self.data = data
        self.error = nil
    }
}

/// Known Better Auth error codes.
public enum BetterAuthErrorCode: String, Codable {
    case invalidCredentials = "INVALID_CREDENTIALS"
    case unauthorized = "UNAUTHORIZED"
    case userNotFound = "USER_NOT_FOUND"
    case internalError = "INTERNAL_ERROR"
}

/// Error payload returned by Better Auth.
public struct APIError: Codable, Error {
    public let code: String?
    public let message: String
    public var knownCode: BetterAuthErrorCode? { code.flatMap(BetterAuthErrorCode.init(rawValue:)) }
}

/// Session model returned by Better Auth.
public struct Session: Codable {
    public let token: String
    public let expiresAt: Date?
    public let createdAt: Date?
    public let updatedAt: Date?

    enum CodingKeys: String, CodingKey {
        case token, expiresAt, createdAt, updatedAt
    }
}

/// User model. Some fields may be omitted depending on provider and consent.
public struct User: Codable {
    public let id: String
    public let email: String?
    public let name: String?
    public let provider: String?
    public let metadata: [String: AnyCodable]?
    public let createdAt: Date?
    public let updatedAt: Date?

    enum CodingKeys: String, CodingKey {
        case id, email, name, provider, metadata, createdAt, updatedAt
    }
}

/// Auth payload combining session and optionally user.
public struct AuthData: Codable {
    public let session: Session
    public let user: User?
}

// Legacy AppleSignInRequest removed in favor of SocialSignInRequest

/// Request body for session refresh.
public struct RefreshRequest: Codable {
    public let refreshToken: String?
    public init(refreshToken: String? = nil) { self.refreshToken = refreshToken }
}

/// Empty payload for endpoints that return only `success`/`error`.
public struct EmptyResponse: Codable {}

// MARK: - Alternate sign-in payloads

/// Envelope for sending an ID token with optional nonce/accessToken.
public struct IdTokenEnvelope: Codable {
    public let token: String
    public let nonce: String?
    public let accessToken: String?

    public init(token: String, nonce: String? = nil, accessToken: String? = nil) {
        self.token = token
        self.nonce = nonce
        self.accessToken = accessToken
    }
}

/// Sign-in request that includes the provider in the body and an `idToken` envelope.
public struct ProviderIdTokenSignInRequest: Codable {
    public let provider: String
    public let idToken: IdTokenEnvelope

    public init(provider: String, idToken: IdTokenEnvelope) {
        self.provider = provider
        self.idToken = idToken
    }
}

/// Social sign-in request (Convex/OpenAPI variant) with string idToken and optional parameters.
public struct SocialSignInRequest: Codable {
    public let provider: String
    public let callbackURL: String?
    public let newUserCallbackURL: String?
    public let errorCallbackURL: String?
    public let disableRedirect: String?
    public let idToken: String
    public let scopes: String?
    public let requestSignUp: String?
    public let loginHint: String?

    public init(provider: String,
                idToken: String,
                callbackURL: String? = nil,
                newUserCallbackURL: String? = nil,
                errorCallbackURL: String? = nil,
                disableRedirect: String? = nil,
                scopes: String? = nil,
                requestSignUp: String? = nil,
                loginHint: String? = nil) {
        self.provider = provider
        self.idToken = idToken
        self.callbackURL = callbackURL
        self.newUserCallbackURL = newUserCallbackURL
        self.errorCallbackURL = errorCallbackURL
        self.disableRedirect = disableRedirect
        self.scopes = scopes
        self.requestSignUp = requestSignUp
        self.loginHint = loginHint
    }
}

/// Social sign-in token response variant: returns redirect flag and token.
public struct SocialSignInTokenResponse: Codable {
    public let redirect: Bool?
    public let token: String?
    public let url: String?
}

/// Optional parameters for social sign-in requests.
public struct SocialSignInOptions: Sendable {
    public var callbackURL: String?
    public var newUserCallbackURL: String?
    public var errorCallbackURL: String?
    public var disableRedirect: String?
    public var scopes: String?
    public var requestSignUp: String?
    public var loginHint: String?

    public init(callbackURL: String? = nil,
                newUserCallbackURL: String? = nil,
                errorCallbackURL: String? = nil,
                disableRedirect: String? = nil,
                scopes: String? = nil,
                requestSignUp: String? = nil,
                loginHint: String? = nil) {
        self.callbackURL = callbackURL
        self.newUserCallbackURL = newUserCallbackURL
        self.errorCallbackURL = errorCallbackURL
        self.disableRedirect = disableRedirect
        self.scopes = scopes
        self.requestSignUp = requestSignUp
        self.loginHint = loginHint
    }
}

/// Refresh token request/response models.
public struct RefreshTokenRequest: Codable {
    public let providerId: String
    public let accountId: String?
    public let userId: String?

    public init(providerId: String, accountId: String? = nil, userId: String? = nil) {
        self.providerId = providerId
        self.accountId = accountId
        self.userId = userId
    }
}

public struct RefreshTokenResponse: Codable {
    public let accessToken: String?
    public let accessTokenExpiresAt: Date?
    public let idToken: String?
    public let refreshToken: String?
    public let refreshTokenExpiresAt: Date?
    public let tokenType: String?
}

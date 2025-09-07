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

/// Request body for Apple sign-in.
public struct AppleSignInRequest: Codable {
    public let identityToken: String
}

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

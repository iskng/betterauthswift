import Foundation
import Security

/// Abstraction for reading/writing the auth token.
public protocol TokenStoring {
    /// Stores a new auth token, replacing any existing one.
    func storeToken(_ token: String) throws
    /// Returns the currently stored token, if any.
    func retrieveToken() -> String?
    /// Deletes the stored token.
    func deleteToken() throws
}

/// Keychain-backed token store.
public final class KeychainTokenStore: TokenStoring {
    private let service: String
    private let account: String

    public init(service: String = Bundle.main.bundleIdentifier ?? "BetterAuthSwift", account: String = "sessionToken") {
        self.service = service
        self.account = account
    }

    public func storeToken(_ token: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        SecItemDelete(query as CFDictionary)
        var addQuery = query
        addQuery[kSecValueData as String] = token.data(using: .utf8)!
        let status = SecItemAdd(addQuery as CFDictionary, nil)
        if status != errSecSuccess {
            throw BetterAuthError.storageStatus(status)
        }
    }

    public func retrieveToken() -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data, let token = String(data: data, encoding: .utf8) else {
            return nil
        }
        return token
    }

    public func deleteToken() throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        let status = SecItemDelete(query as CFDictionary)
        if status != errSecSuccess && status != errSecItemNotFound {
            throw BetterAuthError.storageStatus(status)
        }
    }
}

/// Notification emitted when the token changes.
public extension Notification.Name {
    static let betterAuthTokenDidChange = Notification.Name("BetterAuthTokenDidChange")
}

public enum BetterAuthTokenUserInfoKey {
    public static let oldToken = "oldToken"
    public static let newToken = "newToken"
}

/// Decorator that posts `betterAuthTokenDidChange` on store/delete.
public final class NotifyingTokenStore: TokenStoring {
    private let base: TokenStoring
    private let center: NotificationCenter

    public init(base: TokenStoring, center: NotificationCenter = .default) {
        self.base = base
        self.center = center
    }

    public func storeToken(_ token: String) throws {
        let old = base.retrieveToken()
        try base.storeToken(token)
        var userInfo: [String: Any] = [:]
        if let old = old { userInfo[BetterAuthTokenUserInfoKey.oldToken] = old }
        userInfo[BetterAuthTokenUserInfoKey.newToken] = token
        center.post(name: .betterAuthTokenDidChange, object: nil, userInfo: userInfo)
    }

    public func retrieveToken() -> String? {
        base.retrieveToken()
    }

    public func deleteToken() throws {
        let old = base.retrieveToken()
        try base.deleteToken()
        var userInfo: [String: Any] = [:]
        if let old = old { userInfo[BetterAuthTokenUserInfoKey.oldToken] = old }
        center.post(name: .betterAuthTokenDidChange, object: nil, userInfo: userInfo)
    }
}

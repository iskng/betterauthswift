import Foundation

/// Top-level error type for BetterAuthSwift operations.
public enum BetterAuthError: Error, LocalizedError {
    case invalidURL(String)
    case network(Error)
    case invalidResponse(Int, Data?)
    case decoding(Error)
    case appleAuthorization(Error)
    case missingToken
    case storageStatus(OSStatus)
    case api(APIError)

    public var errorDescription: String? {
        switch self {
        case .api(let apiError):
            if let code = apiError.code {
                return "API Error \(code): \(apiError.message)"
            }
            return "API Error: \(apiError.message)"
        case .invalidURL(let url):
            return "Invalid URL: \(url)"
        case .network(let error):
            return "Network error: \(error.localizedDescription)"
        case .invalidResponse(let status, _):
            return "Invalid response: HTTP \(status)"
        case .decoding(let error):
            return "Decoding error: \(error.localizedDescription)"
        case .appleAuthorization(let error):
            return "Apple sign-in failed: \(error.localizedDescription)"
        case .missingToken:
            return "No auth token available"
        case .storageStatus(let status):
            if let msg = SecCopyErrorMessageString(status, nil) as String? {
                return "Storage error: \(msg) (\(status))"
            }
            return "Storage error: \(status)"
        }
    }
}

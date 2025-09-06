# BetterAuthSwift

Type-safe Swift client for the Better Auth backend API (v0.4.x). Supports Sign in with Apple, session management, refresh, and sign-out. Stores tokens securely in Keychain and emits notifications on token changes.

## Features

- Async/await URLSession HTTP client
- Secure Keychain token storage
- Sign in with Apple via AuthenticationServices
- Extensible provider protocol (`SignInTokenProvider`)
- Flexible decoding of `{ success, data, error }` wrappers
- Token change notifications via `NotificationCenter`

## Requirements

- iOS 13.0+ or macOS 10.15+
- Swift 5.9+

## Installation (SPM)

Add the package to Xcode or `Package.swift` as a dependency.

## Usage

```swift
import BetterAuthSwift

let client = try BetterAuthClient(baseURL: "https://your-server.com")

// Sign in with Apple (iOS)
// Provide a presentation anchor from your scene/window if desired
// let window: UIWindow = ...
// let anchor = window
// let response = try await client.signInWithApple(presentationAnchor: anchor)

// Get session
let session = try await client.getSession()

// Read current token
let token = client.currentToken

// Sign out
try await client.signOut()
```

### Token Change Notifications

```swift
let center = NotificationCenter()
let client = try BetterAuthClient(baseURL: "https://your-server.com", notificationCenter: center)

let observer = center.addObserver(forName: .betterAuthTokenDidChange, object: nil, queue: .main) { note in
    let oldToken = note.userInfo?[BetterAuthTokenUserInfoKey.oldToken] as? String
    let newToken = note.userInfo?[BetterAuthTokenUserInfoKey.newToken] as? String
    print("Token changed from", oldToken ?? "nil", "to", newToken ?? "nil")
}
```

### Custom Provider

```swift
struct GoogleProvider: SignInTokenProvider {
    func fetchToken() async throws -> String { /* obtain Google access token */ "access-token" }
    var tokenKey: String { "accessToken" }
}

let resp = try await client.signIn(with: GoogleProvider(), providerName: "google")
```

## License

MIT


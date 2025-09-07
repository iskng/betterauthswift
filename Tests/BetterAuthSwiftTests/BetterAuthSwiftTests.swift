import XCTest
@testable import BetterAuthSwift

final class BetterAuthSwiftTests: XCTestCase {
    func testDecodeAPIResponseSuccess() throws {
        let json = """
        {
          "success": true,
          "data": {
            "session": {"token": "t1", "expiresAt": "2025-01-01T00:00:00Z"},
            "user": {"id": "u1", "email": "user@example.com"}
          }
        }
        """.data(using: .utf8)!

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let resp = try decoder.decode(APIResponse<AuthData>.self, from: json)
        XCTAssertEqual(resp.success, true)
        XCTAssertEqual(resp.data?.session.token, "t1")
        XCTAssertEqual(resp.data?.user?.id, "u1")
    }

    func testDecodeAPIResponseError() throws {
        let json = """
        {"error": {"code": "INVALID_CREDENTIALS", "message": "Invalid token"}}
        """.data(using: .utf8)!
        let resp = try JSONDecoder().decode(APIResponse<EmptyResponse>.self, from: json)
        XCTAssertEqual(resp.success, false)
        XCTAssertNil(resp.data)
        XCTAssertEqual(resp.error?.code, "INVALID_CREDENTIALS")
    }

    func testClientGetSessionStoresToken() async throws {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [MockURLProtocol.self]
        MockURLProtocol.requestHandler = { request in
            XCTAssertEqual(request.url?.path, "/api/auth/get-session")
            let body = """
            {"success": true, "data": {"session": {"token": "abc123"}, "user": {"id": "u"}}}
            """.data(using: .utf8)!
            return (200, body)
        }
        let session = URLSession(configuration: config)
        let store = InMemoryTokenStore()
        let client = try BetterAuthClient(baseURL: "https://example.com", session: session, tokenStore: store)
        let resp = try await client.getSession()
        XCTAssertEqual(resp.data?.session.token, "abc123")
        XCTAssertEqual(store.retrieveToken(), "abc123")
    }

    func testSignOutDeletesToken() async throws {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [MockURLProtocol.self]
        MockURLProtocol.requestHandler = { request in
            XCTAssertEqual(request.url?.path, "/api/auth/sign-out")
            let body = """
            {"success": true}
            """.data(using: .utf8)!
            return (200, body)
        }
        let session = URLSession(configuration: config)
        let store = InMemoryTokenStore()
        try store.storeToken("temp-token")
        let client = try BetterAuthClient(baseURL: "https://example.com", session: session, tokenStore: store)
        try await client.signOut()
        XCTAssertNil(store.retrieveToken())
    }

    func testDecodeWithoutSuccessKey() throws {
        let json = """
        {"data": {"session": {"token": "t2"}, "user": {"id": "u2"}}}
        """.data(using: .utf8)!
        let resp = try JSONDecoder().decode(APIResponse<AuthData>.self, from: json)
        XCTAssertEqual(resp.success, true)
        XCTAssertEqual(resp.data?.session.token, "t2")
    }

    func testAuthorizationHeaderAttached() async throws {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [MockURLProtocol.self]
        MockURLProtocol.requestHandler = { request in
            XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer tk")
            let body = """
            {"success": true, "data": {"session": {"token": "tk"}, "user": {"id": "u"}}}
            """.data(using: .utf8)!
            return (200, body)
        }
        let session = URLSession(configuration: config)
        let store = InMemoryTokenStore()
        try store.storeToken("tk")
        let client = try BetterAuthClient(baseURL: "https://example.com", session: session, tokenStore: store)
        _ = try await client.getSession()
    }

    func testNon200WithAPIErrorThrows() async {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [MockURLProtocol.self]
        MockURLProtocol.requestHandler = { _ in
            let body = """
            {"error": {"code": "UNAUTHORIZED", "message": "unauth"}}
            """.data(using: .utf8)!
            return (401, body)
        }
        let session = URLSession(configuration: config)
        let client = try! BetterAuthClient(baseURL: "https://example.com", session: session, tokenStore: InMemoryTokenStore())
        do {
            _ = try await client.getSession()
            XCTFail("Expected error")
        } catch let err as BetterAuthError {
            switch err {
            case .api(let apiErr):
                XCTAssertEqual(apiErr.code, "UNAUTHORIZED")
            default:
                XCTFail("Unexpected error: \(err)")
            }
        } catch {
            XCTFail("Wrong error type: \(error)")
        }
    }

    func testRefreshTokenDecoding() async throws {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [MockURLProtocol.self]
        MockURLProtocol.requestHandler = { request in
            XCTAssertEqual(request.url?.path, "/api/auth/refresh-token")
            let body = """
            {"accessToken": "acc", "idToken": "idt", "refreshToken": "rft", "tokenType": "Bearer"}
            """.data(using: .utf8)!
            return (200, body)
        }
        let session = URLSession(configuration: config)
        let client = try BetterAuthClient(baseURL: "https://example.com", session: session, tokenStore: InMemoryTokenStore())
        let resp = try await client.refreshToken(providerId: "apple")
        XCTAssertEqual(resp.accessToken, "acc")
        XCTAssertEqual(resp.idToken, "idt")
    }

    func testGenericProviderSignInSendsSocialBody() async throws {
        struct FakeProvider: SignInTokenProvider {
            func fetchToken() async throws -> String { "goog-token" }
            var tokenKey: String { "idToken" }
        }
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [MockURLProtocol.self]
        MockURLProtocol.requestHandler = { request in
            XCTAssertEqual(request.url?.path, "/api/auth/sign-in/social")
            let bodyData: Data? = {
                if let data = request.httpBody { return data }
                if let stream = request.httpBodyStream {
                    stream.open()
                    defer { stream.close() }
                    var buffer = Data()
                    let chunkSize = 1024
                    let temp = UnsafeMutablePointer<UInt8>.allocate(capacity: chunkSize)
                    defer { temp.deallocate() }
                    while stream.hasBytesAvailable {
                        let read = stream.read(temp, maxLength: chunkSize)
                        if read > 0 { buffer.append(temp, count: read) } else { break }
                    }
                    return buffer
                }
                return nil
            }()
            if let data = bodyData, let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                XCTAssertEqual(obj["provider"] as? String, "google")
                XCTAssertEqual(obj["idToken"] as? String, "goog-token")
            } else {
                XCTFail("Missing body")
            }
            let body = """
            {"success": true, "data": {"session": {"token": "tk"}, "user": {"id": "u"}}}
            """.data(using: .utf8)!
            return (200, body)
        }
        let session = URLSession(configuration: config)
        let store = InMemoryTokenStore()
        let client = try BetterAuthClient(baseURL: "https://example.com", session: session, tokenStore: store)
        let resp = try await client.signIn(with: FakeProvider(), providerName: "google")
        XCTAssertEqual(resp.data?.session.token, "tk")
        XCTAssertEqual(store.retrieveToken(), "tk")
    }

    func testAppleSignInUsesSocialEndpoint() async throws {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [MockURLProtocol.self]
        MockURLProtocol.requestHandler = { request in
            XCTAssertEqual(request.url?.path, "/api/auth/sign-in/social")
            XCTAssertEqual(request.httpMethod, "POST")
            let bodyData: Data = {
                if let d = request.httpBody { return d }
                if let s = request.httpBodyStream {
                    s.open(); defer { s.close() }
                    var data = Data(); var buf = [UInt8](repeating: 0, count: 1024)
                    while s.hasBytesAvailable { let r = s.read(&buf, maxLength: buf.count); if r > 0 { data.append(buf, count: r) } else { break } }
                    return data
                }
                return Data()
            }()
            let json = try! JSONSerialization.jsonObject(with: bodyData) as! [String: Any]
            XCTAssertEqual(json["provider"] as? String, "apple")
            XCTAssertEqual(json["idToken"] as? String, "apple-token")
            let resp = """
            {"redirect": false, "token": "st"}
            """.data(using: .utf8)!
            return (200, resp)
        }
        let session = URLSession(configuration: config)
        let store = InMemoryTokenStore()
        let client = try BetterAuthClient(baseURL: "https://example.com", session: session, tokenStore: store)
        let resp = try await client.signInWithApple(identityToken: "apple-token")
        XCTAssertEqual(resp.data?.session.token, "st")
        XCTAssertEqual(store.retrieveToken(), "st")
    }

    func testCurrentTokenGetterAndNotificationsOnStore() async throws {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [MockURLProtocol.self]
        MockURLProtocol.requestHandler = { _ in
            let body = """
            {"success": true, "data": {"session": {"token": "tok1"}, "user": {"id": "u"}}}
            """.data(using: .utf8)!
            return (200, body)
        }
        let session = URLSession(configuration: config)
        let store = InMemoryTokenStore()
        let client = try BetterAuthClient(baseURL: "https://example.com", session: session, tokenStore: store)
        let exp = expectation(forNotification: .betterAuthTokenDidChange, object: nil) { note in
            let newToken = note.userInfo?[BetterAuthTokenUserInfoKey.newToken] as? String
            return newToken == "tok1"
        }
        _ = try await client.getSession()
        wait(for: [exp], timeout: 1.0)
        XCTAssertEqual(client.currentToken, "tok1")
    }

    func testNotificationsOnDelete() async throws {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [MockURLProtocol.self]
        MockURLProtocol.requestHandler = { _ in
            let body = """
            {"success": true}
            """.data(using: .utf8)!
            return (200, body)
        }
        let session = URLSession(configuration: config)
        let store = InMemoryTokenStore()
        try store.storeToken("old")
        let client = try BetterAuthClient(baseURL: "https://example.com", session: session, tokenStore: store)
        let exp = expectation(forNotification: .betterAuthTokenDidChange, object: nil) { note in
            let oldToken = note.userInfo?[BetterAuthTokenUserInfoKey.oldToken] as? String
            return oldToken == "old"
        }
        try await client.signOut()
        wait(for: [exp], timeout: 1.0)
    }

    func testCustomNotificationCenterUsed() async throws {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [MockURLProtocol.self]
        MockURLProtocol.requestHandler = { _ in
            let body = """
            {"success": true, "data": {"session": {"token": "tokX"}, "user": {"id": "u"}}}
            """.data(using: .utf8)!
            return (200, body)
        }
        let session = URLSession(configuration: config)
        let center = NotificationCenter()
        let store = InMemoryTokenStore()
        let client = try BetterAuthClient(baseURL: "https://example.com", session: session, tokenStore: store, notificationCenter: center)
        let exp = expectation(description: "custom center")
        let token = center.addObserver(forName: .betterAuthTokenDidChange, object: nil, queue: .main) { note in
            let newToken = note.userInfo?[BetterAuthTokenUserInfoKey.newToken] as? String
            if newToken == "tokX" { exp.fulfill() }
        }
        _ = try await client.getSession()
        await fulfillment(of: [exp], timeout: 1.0)
        center.removeObserver(token)
    }
}

// MARK: - Test helpers

final class InMemoryTokenStore: TokenStoring {
    private var token: String?
    func storeToken(_ token: String) throws { self.token = token }
    func retrieveToken() -> String? { token }
    func deleteToken() throws { token = nil }
}

final class MockURLProtocol: URLProtocol {
    static var requestHandler: ((URLRequest) -> (Int, Data))?

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let handler = MockURLProtocol.requestHandler else {
            client?.urlProtocol(self, didFailWithError: NSError(domain: "NoHandler", code: 0))
            return
        }
        let (status, data) = handler(request)
        let response = HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: nil, headerFields: ["Content-Type": "application/json"])!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: data)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

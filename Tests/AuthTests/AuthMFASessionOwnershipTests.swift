import Auth
import Foundation
import XCTest

@MainActor
final class AuthMFASessionOwnershipTests: XCTestCase {
  func testHeldSDKVerificationCannotReplaceNewerStoredAuthSession() async throws {
    let started = expectation(description: "SDK sent A's verification request")
    let fixture = try MFAVerificationFixture(verifyStarted: started)
    let recorder = fixture.storage
    let subscription = await fixture.auth.onAuthStateChange { event, session in
      recorder.record(event, session: session)
    }
    defer { subscription.remove() }
    XCTAssertEqual(fixture.auth.currentSession, fixture.initial)

    let pending = Task {
      try await fixture.verifyFreshTOTP()
    }
    await fulfillment(of: [started], timeout: 3)

    // Install B through a real SDK authoritative update while A's response is
    // held by a private transport. Directly editing fixture bytes would miss
    // the SDK's session-epoch transition.
    do {
      let replacement = try await fixture.auth.signIn(
        email: "b@fixture.invalid", password: "fixture-only")
      XCTAssertEqual(replacement, fixture.replacement)
      XCTAssertEqual(fixture.auth.currentSession, fixture.replacement)
    } catch {
      await fixture.transport.releaseVerification()
      _ = await pending.result
      throw error
    }
    let writesBeforeResponse = recorder.writes
    XCTAssertEqual(writesBeforeResponse.count, 1)

    await fixture.transport.releaseVerification()
    _ = await pending.result

    XCTAssertEqual(
      fixture.auth.currentSession, fixture.replacement,
      "A delayed successful verify must not replace B in the SDK's stored session")
    XCTAssertEqual(
      recorder.writes, writesBeforeResponse,
      "An obsolete verification cannot write A, even transiently")
    XCTAssertTrue(
      recorder.verifiedSessions.isEmpty,
      "An obsolete verification cannot announce A as the verified session")
    let requests = await fixture.transport.requests
    XCTAssertEqual(
      requests.map { $0.url?.path },
      [
        "/auth/v1/factors/fixture-factor/challenge",
        "/auth/v1/factors/fixture-factor/verify",
        "/auth/v1/token",
      ])
    XCTAssertEqual(
      requests.prefix(2).map { $0.value(forHTTPHeaderField: "Authorization") },
      [String?](repeating: "Bearer \(fixture.initial.accessToken)", count: 2))
  }

  func testCurrentSDKVerificationStoresElevatedSessionAndEmitsVerification() async throws {
    let fixture = try MFAVerificationFixture()
    let recorder = fixture.storage
    let subscription = await fixture.auth.onAuthStateChange { event, session in
      recorder.record(event, session: session)
    }
    defer { subscription.remove() }
    let originalAssurance = try await fixture.auth.mfa.getAuthenticatorAssuranceLevel()
    XCTAssertEqual(originalAssurance.currentLevel, "aal1")

    try await fixture.verifyFreshTOTP()

    XCTAssertEqual(fixture.auth.currentSession, fixture.elevated)
    XCTAssertEqual(recorder.writes.count, 1)
    XCTAssertEqual(recorder.verifiedSessions, [fixture.elevated])
    let elevatedAssurance = try await fixture.auth.mfa.getAuthenticatorAssuranceLevel()
    XCTAssertEqual(elevatedAssurance.currentLevel, "aal2")
    XCTAssertTrue(elevatedAssurance.currentAuthenticationMethods.contains { $0.method == "totp" })
  }

  func testCombinedVerificationCannotVerifyHeldChallengeAfterReplacement() async throws {
    let started = expectation(description: "A challenge has been sent")
    let fixture = try MFAVerificationFixture(challengeStarted: started)
    let pending = Task { try await fixture.verifyCombined() }
    await fulfillment(of: [started], timeout: 3)
    try await replaceAndRelease(fixture, pending: pending)

    XCTAssertEqual(fixture.auth.currentSession, fixture.replacement)
    XCTAssertEqual(fixture.storage.writes.count, 1)
    let requests = await fixture.transport.requests
    XCTAssertEqual(
      requests.map { $0.url?.path },
      ["/auth/v1/factors/fixture-factor/challenge", "/auth/v1/token"])
  }

  func testSameUserAuthoritativeReplacementChangesTheVerificationEpoch() async throws {
    let started = expectation(description: "The first visit sent verification")
    let fixture = try MFAVerificationFixture(verifyStarted: started, replaceWithSameOwner: true)
    XCTAssertEqual(fixture.initial.user.id, fixture.replacement.user.id)
    XCTAssertNotEqual(fixture.initial.accessToken, fixture.replacement.accessToken)
    let pending = Task { try await fixture.verifyCombined() }
    await fulfillment(of: [started], timeout: 3)
    try await replaceAndRelease(fixture, pending: pending)

    XCTAssertEqual(fixture.auth.currentSession, fixture.replacement)
    XCTAssertEqual(fixture.storage.writes.count, 1)
  }

  func testCancelledHeldVerificationCannotPromoteTheCurrentSession() async throws {
    let started = expectation(description: "Verification dispatched before cancellation")
    let fixture = try MFAVerificationFixture(verifyStarted: started)
    let pending = Task { try await fixture.verifyCombined() }
    await fulfillment(of: [started], timeout: 3)
    pending.cancel()
    await fixture.transport.releaseVerification()
    do {
      try await pending.value
      XCTFail("Cancelled verification must not return an accepted promotion")
    } catch {
      XCTAssertTrue(error is CancellationError)
    }
    XCTAssertEqual(fixture.auth.currentSession, fixture.initial)
    XCTAssertTrue(fixture.storage.writes.isEmpty)
  }

  func testHeldVerificationCannotRestoreASignedOutSession() async throws {
    let started = expectation(description: "Verification dispatched before sign-out")
    let fixture = try MFAVerificationFixture(verifyStarted: started)
    let pending = Task { try await fixture.verifyCombined() }
    await fulfillment(of: [started], timeout: 3)
    do {
      try await fixture.auth.signOut()
    } catch {
      await fixture.transport.releaseVerification()
      _ = await pending.result
      throw error
    }
    XCTAssertNil(fixture.auth.currentSession)
    await fixture.transport.releaseVerification()
    _ = await pending.result
    XCTAssertNil(fixture.auth.currentSession)
    XCTAssertTrue(fixture.storage.writes.isEmpty)
  }

  func testLateSessionMissingErrorCannotRemoveReplacement() async throws {
    let started = expectation(description: "Old-session request has been sent")
    let fixture = try MFAVerificationFixture(verifyStarted: started, outcome: .sessionMissing)
    let pending = Task { try await fixture.verifyCombined() }
    await fulfillment(of: [started], timeout: 3)
    try await replaceAndRelease(fixture, pending: pending)

    XCTAssertEqual(fixture.auth.currentSession, fixture.replacement)
    XCTAssertEqual(fixture.storage.writes.count, 1)
  }

  func testCurrentSessionMissingStillClearsTheOwningSession() async throws {
    let fixture = try MFAVerificationFixture(outcome: .sessionMissing)
    do {
      try await fixture.verifyCombined()
      XCTFail("Missing session must surface")
    } catch let error as AuthError {
      XCTAssertEqual(error, .sessionMissing)
    }
    XCTAssertNil(fixture.auth.currentSession)
    XCTAssertTrue(fixture.storage.writes.isEmpty)
  }

  func testInvalidCodeAndOfflineKeepCurrentSessionWithoutPromotion() async throws {
    let invalid = try MFAVerificationFixture(outcome: .invalidCode)
    do {
      try await invalid.verifyCombined()
      XCTFail("Invalid code must surface")
    } catch let error as AuthError {
      XCTAssertEqual(error.errorCode, .mfaVerificationFailed)
    }
    XCTAssertEqual(invalid.auth.currentSession, invalid.initial)
    XCTAssertTrue(invalid.storage.writes.isEmpty)

    let offline = try MFAVerificationFixture(outcome: .unavailable)
    do {
      try await offline.verifyCombined()
      XCTFail("Network failure must surface")
    } catch let error as URLError {
      XCTAssertEqual(error.code, .notConnectedToInternet)
    }
    XCTAssertEqual(offline.auth.currentSession, offline.initial)
    XCTAssertTrue(offline.storage.writes.isEmpty)
  }

  func testCombinedVerificationUsesRefreshedBearerAfterHeldChallenge() async throws {
    let started = expectation(description: "Challenge uses the original session")
    let fixture = try MFAVerificationFixture(challengeStarted: started)
    let pending = Task { try await fixture.verifyCombined() }
    await fulfillment(of: [started], timeout: 3)
    try await refreshAndRelease(fixture, pending: pending)
    try await pending.value

    XCTAssertEqual(fixture.auth.currentSession, fixture.elevated)
    let assurance = try await fixture.auth.mfa.getAuthenticatorAssuranceLevel()
    XCTAssertEqual(assurance.currentLevel, "aal2")
    try await assertRefreshedVerificationBearer(fixture)
  }

  func testSessionMissingFromRefreshedVerifyRemovesThatExactSession() async throws {
    let started = expectation(description: "Challenge precedes refresh")
    let fixture = try MFAVerificationFixture(challengeStarted: started, outcome: .sessionMissing)
    let pending = Task { try await fixture.verifyCombined() }
    await fulfillment(of: [started], timeout: 3)
    try await refreshAndRelease(fixture, pending: pending)
    do {
      try await pending.value
      XCTFail("Missing refreshed session must surface")
    } catch let error as AuthError {
      XCTAssertEqual(error, .sessionMissing)
    }

    XCTAssertNil(fixture.auth.currentSession)
    try await assertRefreshedVerificationBearer(fixture)
  }

  func testOldVerifySessionMissingCannotRemoveNewerSameEpochRefresh() async throws {
    let started = expectation(description: "Verify used the old token before refresh")
    let fixture = try MFAVerificationFixture(verifyStarted: started, outcome: .sessionMissing)
    let pending = Task { try await fixture.verifyCombined() }
    await fulfillment(of: [started], timeout: 3)
    try await refreshAndRelease(fixture, pending: pending)
    do {
      try await pending.value
      XCTFail("Missing old session must surface")
    } catch let error as AuthError {
      XCTAssertEqual(error, .sessionMissing)
    }

    XCTAssertEqual(fixture.auth.currentSession, fixture.refreshed)
    XCTAssertEqual(fixture.storage.writes.count, 1)
  }

  private func refreshAndRelease(_ fixture: MFAVerificationFixture, pending: Task<Void, any Error>)
    async throws
  {
    do {
      let refreshed = try await fixture.auth.refreshSession()
      XCTAssertEqual(refreshed, fixture.refreshed)
      XCTAssertEqual(fixture.auth.currentSession, fixture.refreshed)
    } catch {
      await fixture.transport.releaseVerification()
      _ = await pending.result
      throw error
    }
    await fixture.transport.releaseVerification()
  }

  private func assertRefreshedVerificationBearer(_ fixture: MFAVerificationFixture) async throws {
    let requests = await fixture.transport.requests
    XCTAssertEqual(
      requests.map { $0.url?.path },
      [
        "/auth/v1/factors/fixture-factor/challenge", "/auth/v1/token",
        "/auth/v1/factors/fixture-factor/verify",
      ])
    let challenge = try XCTUnwrap(requests.first)
    let verify = try XCTUnwrap(requests.last)
    XCTAssertEqual(
      challenge.value(forHTTPHeaderField: "Authorization"), "Bearer \(fixture.initial.accessToken)")
    XCTAssertEqual(
      verify.value(forHTTPHeaderField: "Authorization"), "Bearer \(fixture.refreshed.accessToken)")
  }

  private func replaceAndRelease(_ fixture: MFAVerificationFixture, pending: Task<Void, any Error>)
    async throws
  {
    do {
      let replacement = try await fixture.auth.signIn(
        email: "b@fixture.invalid", password: "fixture-only")
      XCTAssertEqual(replacement, fixture.replacement)
      XCTAssertEqual(fixture.auth.currentSession, fixture.replacement)
    } catch {
      await fixture.transport.releaseVerification()
      _ = await pending.result
      throw error
    }
    await fixture.transport.releaseVerification()
    _ = await pending.result
  }
}

@MainActor
private struct MFAVerificationFixture {
  let auth: AuthClient
  let initial: Session
  let elevated: Session
  let replacement: Session
  let refreshed: Session
  let storage: MFAVerificationStorage
  let transport: MFAVerificationTransport

  init(
    verifyStarted: XCTestExpectation? = nil, challengeStarted: XCTestExpectation? = nil,
    replaceWithSameOwner: Bool = false, outcome: VerificationOutcome = .success
  ) throws {
    let owner = UUID()
    let expiration = Date().timeIntervalSince1970.rounded(.down) + 3_600
    let initial = Self.session(
      userID: owner, expiration: expiration, level: "aal1", method: "password", tokenLabel: "a")
    let elevated = Self.session(
      userID: owner, expiration: expiration, level: "aal2", method: "totp", tokenLabel: "a-elevated"
    )
    let replacement = Self.session(
      userID: replaceWithSameOwner ? owner : UUID(), expiration: expiration, level: "aal1",
      method: "password", tokenLabel: "b")
    let refreshed = Self.session(
      userID: owner, expiration: expiration, level: "aal1", method: "password",
      tokenLabel: "a-refreshed")
    let storage = try MFAVerificationStorage(initial: initial)
    let transport = MFAVerificationTransport(
      verifyBody: try AuthClient.Configuration.jsonEncoder.encode(elevated),
      replacementBody: try AuthClient.Configuration.jsonEncoder.encode(replacement),
      refreshBody: try AuthClient.Configuration.jsonEncoder.encode(refreshed),
      verifyStarted: verifyStarted,
      challengeStarted: challengeStarted,
      outcome: outcome
    )
    let auth = AuthClient(
      configuration: .init(
        url: URL(string: "https://kapture-mfa-fixture.invalid/auth/v1")!,
        storageKey: MFAVerificationStorage.key,
        localStorage: storage,
        fetch: { try await transport.fetch($0) },
        autoRefreshToken: false,
        emitLocalSessionAsInitialSession: true
      ))
    self.auth = auth
    self.initial = initial
    self.elevated = elevated
    self.replacement = replacement
    self.refreshed = refreshed
    self.storage = storage
    self.transport = transport
  }

  func verifyFreshTOTP() async throws {
    let challenge = try await auth.mfa.challenge(
      params: MFAChallengeParams(factorId: "fixture-factor"))
    _ = try await auth.mfa.verify(
      params: MFAVerifyParams(factorId: "fixture-factor", challengeId: challenge.id, code: "123456")
    )
  }

  func verifyCombined() async throws {
    _ = try await auth.mfa.challengeAndVerify(
      params: MFAChallengeAndVerifyParams(factorId: "fixture-factor", code: "123456"))
  }

  private static func session(
    userID: UUID, expiration: TimeInterval, level: String, method: String, tokenLabel: String
  ) -> Session {
    let payload = Data(
      """
      {"sub":"\(userID.uuidString.lowercased())","exp":\(Int(expiration)),"aal":"\(level)","jti":"\(tokenLabel)","amr":[{"method":"\(method)","timestamp":1700000000}]}
      """.utf8
    ).base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
    let fixedDate = Date(timeIntervalSince1970: 1_700_000_000)
    return Session(
      accessToken: "eyJhbGciOiJIUzI1NiJ9.\(payload).Zml4dHVyZQ",
      tokenType: "bearer", expiresIn: 3_600, expiresAt: expiration,
      refreshToken: "fixture-only-refresh-\(tokenLabel)",
      user: Auth.User(
        id: userID, appMetadata: [:], userMetadata: [:], aud: "authenticated",
        createdAt: fixedDate, updatedAt: fixedDate)
    )
  }
}

private final class MFAVerificationStorage: AuthLocalStorage, @unchecked Sendable {
  static let key = "kapture-mfa-ownership-fixture"
  private let lock = NSLock()
  private var sessionData: Data?
  private var sessionWrites: [Data] = []
  private var verificationEvents: [Session] = []

  init(initial: Session) throws {
    sessionData = try JSONEncoder().encode(initial)
  }

  var writes: [Data] { lock.withLock { sessionWrites } }
  var verifiedSessions: [Session] { lock.withLock { verificationEvents } }

  func store(key: String, value: Data) throws {
    guard key == Self.key else { return }
    lock.withLock {
      sessionData = value
      sessionWrites.append(value)
    }
  }

  func retrieve(key: String) throws -> Data? {
    guard key == Self.key else { return nil }
    return lock.withLock { sessionData }
  }

  func remove(key: String) throws {
    guard key == Self.key else { return }
    lock.withLock { sessionData = nil }
  }

  func record(_ event: AuthChangeEvent, session: Session?) {
    guard event == .mfaChallengeVerified, let session else { return }
    lock.withLock { verificationEvents.append(session) }
  }
}

private enum VerificationOutcome: Sendable {
  case success
  case sessionMissing
  case invalidCode
  case unavailable
}

private actor MFAVerificationTransport {
  private let verifyBody: Data
  private let replacementBody: Data
  private let refreshBody: Data
  private let verifyStarted: XCTestExpectation?
  private let challengeStarted: XCTestExpectation?
  private let outcome: VerificationOutcome
  private var released = false
  private var verification: CheckedContinuation<Void, Never>?
  private(set) var requests: [URLRequest] = []

  init(
    verifyBody: Data, replacementBody: Data, refreshBody: Data, verifyStarted: XCTestExpectation?,
    challengeStarted: XCTestExpectation?, outcome: VerificationOutcome
  ) {
    self.verifyBody = verifyBody
    self.replacementBody = replacementBody
    self.refreshBody = refreshBody
    self.verifyStarted = verifyStarted
    self.challengeStarted = challengeStarted
    self.outcome = outcome
  }

  func fetch(_ request: URLRequest) async throws -> (Data, URLResponse) {
    requests.append(request)
    guard let url = request.url, url.host == "kapture-mfa-fixture.invalid",
      request.httpMethod == "POST"
    else {
      throw URLError(.unsupportedURL)
    }
    let data: Data
    let status: Int
    switch url.path {
    case "/auth/v1/factors/fixture-factor/challenge":
      await hold(challengeStarted)
      data = Data(#"{"id":"fixture-challenge","type":"totp","expires_at":2000000000}"#.utf8)
      status = 200
    case "/auth/v1/factors/fixture-factor/verify":
      await hold(verifyStarted)
      switch outcome {
      case .success:
        data = verifyBody
        status = 200
      case .sessionMissing:
        data = Data(#"{"code":"session_not_found","msg":"Fixture session missing"}"#.utf8)
        status = 401
      case .invalidCode:
        data = Data(#"{"code":"mfa_verification_failed","msg":"Fixture invalid code"}"#.utf8)
        status = 422
      case .unavailable:
        throw URLError(.notConnectedToInternet)
      }
    case "/auth/v1/token" where url.query == "grant_type=password":
      data = replacementBody
      status = 200
    case "/auth/v1/token" where url.query == "grant_type=refresh_token":
      data = refreshBody
      status = 200
    case "/auth/v1/logout":
      data = Data()
      status = 204
    default:
      throw URLError(.unsupportedURL)
    }
    guard
      let response = HTTPURLResponse(
        url: url, statusCode: status, httpVersion: nil,
        headerFields: [
          "Content-Type": "application/json",
          "X-Supabase-Api-Version": "2024-01-01",
        ])
    else {
      throw URLError(.badServerResponse)
    }
    return (data, response)
  }

  private func hold(_ expectation: XCTestExpectation?) async {
    guard let expectation, !released else { return }
    // Deliberately keep waiting when the caller is cancelled.
    await withCheckedContinuation {
      verification = $0
      expectation.fulfill()
    }
  }

  func releaseVerification() {
    released = true
    verification?.resume()
    verification = nil
  }
}

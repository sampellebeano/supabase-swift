//
//  SessionManagerTests.swift
//
//
//  Created by Guilherme Souza on 23/10/23.
//

import ConcurrencyExtras
import CustomDump
import InlineSnapshotTesting
import TestHelpers
import XCTest
import XCTestDynamicOverlay

@testable import Auth

final class SessionManagerTests: XCTestCase {
  var http: HTTPClientMock!

  let clientID = AuthClientID()

  var sut: SessionManager {
    Dependencies[clientID].sessionManager
  }

  override func setUp() {
    super.setUp()

    http = HTTPClientMock()
    configure(clientID: clientID, http: http)
  }

  @discardableResult
  private func configure(clientID: AuthClientID, http: HTTPClientMock) -> SessionManager {
    Dependencies[clientID] = .init(
      configuration: .init(
        url: clientURL,
        localStorage: InMemoryLocalStorage(),
        autoRefreshToken: false
      ),
      http: http,
      api: APIClient(clientID: clientID),
      codeVerifierStorage: .mock,
      sessionStorage: SessionStorage.live(clientID: clientID),
      sessionManager: SessionManager.live(clientID: clientID)
    )

    return Dependencies[clientID].sessionManager
  }

  #if !os(Windows) && !os(Linux) && !os(Android)
    override func invokeTest() {
      withMainSerialExecutor {
        super.invokeTest()
      }
    }
  #endif

  func testSession_shouldFailWithSessionNotFound() async {
    do {
      _ = try await sut.session()
      XCTFail("Expected a \(AuthError.sessionMissing) failure")
    } catch {
      assertInlineSnapshot(of: error, as: .dump) {
        """
        - AuthError.sessionMissing

        """
      }
    }
  }

  func testSession_shouldReturnValidSession() async throws {
    let session = Session.validSession
    Dependencies[clientID].sessionStorage.store(session)

    let returnedSession = try await sut.session()
    expectNoDifference(returnedSession, session)
  }

  func testSession_shouldRefreshSession_whenCurrentSessionExpired() async throws {
    let currentSession = Session.expiredSession
    Dependencies[clientID].sessionStorage.store(currentSession)

    let validSession = Session.validSession

    let refreshSessionCallCount = LockIsolated(0)

    let (refreshSessionStream, refreshSessionContinuation) = AsyncStream<Session>.makeStream()

    await http.when(
      { $0.url.path.contains("/token") },
      return: { _ in
        refreshSessionCallCount.withValue { $0 += 1 }
        let session = await refreshSessionStream.first(where: { _ in true })!
        return .stub(session)
      }
    )

    // Fire N tasks and call sut.session()
    let tasks = (0..<10).map { _ in
      Task { [weak self] in
        try await self?.sut.session()
      }
    }

    await Task.yield()

    refreshSessionContinuation.yield(validSession)
    refreshSessionContinuation.finish()

    // Await for all tasks to complete.
    var result: [Result<Session?, Error>] = []
    for task in tasks {
      let value = await task.result
      result.append(value)
    }

    // Verify that refresher and storage was called only once.
    expectNoDifference(refreshSessionCallCount.value, 1)
    expectNoDifference(
      try result.map { try $0.get()?.accessToken },
      (0..<10).map { _ in validSession.accessToken }
    )
  }

  func testRefreshThatFinishesAfterAuthoritativeReplacementDoesNotOverwriteTheReplacement()
    async throws
  {
    var sessionA = Session.expiredSession
    sessionA.accessToken = "synthetic-account-a-access"
    sessionA.refreshToken = "synthetic-account-a-refresh"
    sessionA.user.id = UUID(uuidString: "00000000-0000-0000-0000-0000000000A1")!

    var recoverySessionB = Session.validSession
    recoverySessionB.accessToken = "synthetic-recovery-b-access"
    recoverySessionB.refreshToken = "synthetic-recovery-b-refresh"
    recoverySessionB.user.id = UUID(uuidString: "00000000-0000-0000-0000-0000000000B1")!

    var refreshedSessionA = Session.validSession
    refreshedSessionA.accessToken = "synthetic-refreshed-a-access"
    refreshedSessionA.refreshToken = "synthetic-refreshed-a-refresh"
    refreshedSessionA.user.id = sessionA.user.id
    let responseSessionA = refreshedSessionA

    Dependencies[clientID].sessionStorage.store(sessionA)

    let (refreshRequestStarted, refreshRequestStartedContinuation) = AsyncStream<Void>.makeStream()
    let (releaseRefreshResponse, releaseRefreshResponseContinuation) = AsyncStream<Void>.makeStream()

    await http.when(
      { $0.url.path.contains("/token") },
      return: { _ in
        refreshRequestStartedContinuation.yield(())
        _ = await releaseRefreshResponse.first(where: { _ in true })
        return .stub(responseSessionA)
      }
    )

    let events = LockIsolated([(AuthChangeEvent, Session?)]())
    let eventToken = Dependencies[clientID].eventEmitter.attach { event, session in
      events.withValue { $0.append((event, session)) }
    }
    defer { eventToken.cancel() }

    let sessionManager = sut
    let refreshTask = Task {
      try await sessionManager.refreshSession(sessionA.refreshToken)
    }

    _ = await refreshRequestStarted.first(where: { _ in true })
    await sut.update(recoverySessionB)

    releaseRefreshResponseContinuation.yield(())
    releaseRefreshResponseContinuation.finish()

    let refreshResult = await refreshTask.result

    XCTAssertEqual(
      Dependencies[clientID].sessionStorage.get()?.refreshToken,
      recoverySessionB.refreshToken,
      "A completed refresh must not overwrite the newer recovery session."
    )
    XCTAssertFalse(
      events.value.contains { $0.0 == .tokenRefreshed && $0.1?.user.id == sessionA.user.id },
      "A completed refresh must not emit a stale token-refreshed event."
    )
    if case .success = refreshResult {
      XCTFail("A refresh superseded by a recovery session must not return a successful stale session.")
    }
  }

  func testRefreshCleanupErrorsThatFinishAfterReplacementDoNotRemoveTheReplacement()
    async throws
  {
    let cleanupErrorCodes = [
      "session_not_found",
      "session_expired",
      "refresh_token_not_found",
      "refresh_token_already_used",
    ]

    for cleanupErrorCode in cleanupErrorCodes {
      let isolatedClientID = AuthClientID()
      let isolatedHTTP = HTTPClientMock()
      let sessionManager = configure(clientID: isolatedClientID, http: isolatedHTTP)

      var sessionA = Session.expiredSession
      sessionA.accessToken = "synthetic-account-a-access"
      sessionA.refreshToken = "synthetic-account-a-refresh"
      sessionA.user.id = UUID(uuidString: "00000000-0000-0000-0000-0000000000A1")!

      var recoverySessionB = Session.validSession
      recoverySessionB.accessToken = "synthetic-recovery-b-access"
      recoverySessionB.refreshToken = "synthetic-recovery-b-refresh"
      recoverySessionB.user.id = UUID(uuidString: "00000000-0000-0000-0000-0000000000B1")!

      Dependencies[isolatedClientID].sessionStorage.store(sessionA)

      let (refreshRequestStarted, refreshRequestStartedContinuation) = AsyncStream<Void>.makeStream()
      let (releaseRefreshResponse, releaseRefreshResponseContinuation) = AsyncStream<Void>.makeStream()
      let errorResponse = HTTPResponse.stub(
        """
        {
          "error_code": "\(cleanupErrorCode)",
          "message": "Synthetic invalid refresh response"
        }
        """,
        code: 403
      )

      await isolatedHTTP.when(
        { $0.url.path.contains("/token") },
        return: { _ in
          refreshRequestStartedContinuation.yield(())
          _ = await releaseRefreshResponse.first(where: { _ in true })
          return errorResponse
        }
      )

      let events = LockIsolated([(AuthChangeEvent, Session?)]())
      let eventToken = Dependencies[isolatedClientID].eventEmitter.attach { event, session in
        events.withValue { $0.append((event, session)) }
      }
      defer { eventToken.cancel() }

      let refreshTask = Task {
        try await sessionManager.refreshSession(sessionA.refreshToken)
      }

      _ = await refreshRequestStarted.first(where: { _ in true })
      await sessionManager.update(recoverySessionB)

      releaseRefreshResponseContinuation.yield(())
      releaseRefreshResponseContinuation.finish()

      let refreshResult = await refreshTask.result

      XCTAssertEqual(
        Dependencies[isolatedClientID].sessionStorage.get()?.refreshToken,
        recoverySessionB.refreshToken,
        "\(cleanupErrorCode) from a stale refresh must not delete the replacement session."
      )
      XCTAssertFalse(
        events.value.contains { $0.0 == .signedOut },
        "\(cleanupErrorCode) from a stale refresh must not emit signedOut for the replacement."
      )
      if case .success = refreshResult {
        XCTFail("A stale cleanup error must not return a successful session.")
      }
    }
  }

  func testRefreshCleanupErrorStillClearsTheCurrentSession() async throws {
    let sessionA = Session.expiredSession
    Dependencies[clientID].sessionStorage.store(sessionA)

    await http.when(
      { $0.url.path.contains("/token") },
      return: { _ in
        .stub(
          """
          {
            "error_code": "refresh_token_not_found",
            "message": "Synthetic invalid refresh response"
          }
          """,
          code: 403
        )
      }
    )

    let events = LockIsolated([(AuthChangeEvent, Session?)]())
    let eventToken = Dependencies[clientID].eventEmitter.attach { event, session in
      events.withValue { $0.append((event, session)) }
    }
    defer { eventToken.cancel() }

    let refreshResult = await Task {
      try await sut.refreshSession(sessionA.refreshToken)
    }.result

    XCTAssertNil(Dependencies[clientID].sessionStorage.get())
    XCTAssertTrue(events.value.contains { $0.0 == .signedOut })
    if case .success = refreshResult {
      XCTFail("An invalid refresh for the current session must fail.")
    }
  }

  func testStaleRefreshCannotClearTheReplacementRefreshOperation() async throws {
    var sessionA = Session.expiredSession
    sessionA.accessToken = "synthetic-account-a-access"
    sessionA.refreshToken = "synthetic-account-a-refresh"
    sessionA.user.id = UUID(uuidString: "00000000-0000-0000-0000-0000000000A1")!

    var recoverySessionB = Session.validSession
    recoverySessionB.accessToken = "synthetic-recovery-b-access"
    recoverySessionB.refreshToken = "synthetic-recovery-b-refresh"
    recoverySessionB.user.id = UUID(uuidString: "00000000-0000-0000-0000-0000000000B1")!

    var refreshedSessionA = Session.validSession
    refreshedSessionA.accessToken = "synthetic-refreshed-a-access"
    refreshedSessionA.refreshToken = "synthetic-refreshed-a-refresh"
    refreshedSessionA.user.id = sessionA.user.id
    let responseSessionA = refreshedSessionA

    var refreshedSessionB = Session.validSession
    refreshedSessionB.accessToken = "synthetic-refreshed-b-access"
    refreshedSessionB.refreshToken = "synthetic-refreshed-b-refresh"
    refreshedSessionB.user.id = recoverySessionB.user.id
    let responseSessionB = refreshedSessionB

    let sessionARefreshToken = sessionA.refreshToken
    let sessionBRefreshToken = recoverySessionB.refreshToken
    Dependencies[clientID].sessionStorage.store(sessionA)

    let requestedTokens = LockIsolated([String]())
    let (refreshAStarted, refreshAStartedContinuation) = AsyncStream<Void>.makeStream()
    let (releaseRefreshA, releaseRefreshAContinuation) = AsyncStream<Void>.makeStream()
    let (releaseRefreshB, releaseRefreshBContinuation) = AsyncStream<Void>.makeStream()

    await http.when(
      { $0.url.path.contains("/token") },
      return: { request in
        struct RefreshRequest: Decodable {
          let refreshToken: String
        }

        let refreshToken = try AuthClient.Configuration.jsonDecoder.decode(
          RefreshRequest.self,
          from: request.body ?? Data()
        ).refreshToken
        requestedTokens.withValue { $0.append(refreshToken) }

        switch refreshToken {
        case sessionARefreshToken:
          refreshAStartedContinuation.yield(())
          _ = await releaseRefreshA.first(where: { _ in true })
          return .stub(responseSessionA)
        case sessionBRefreshToken:
          _ = await releaseRefreshB.first(where: { _ in true })
          return .stub(responseSessionB)
        default:
          throw URLError(.badServerResponse)
        }
      }
    )

    let refreshA = Task {
      try await sut.refreshSession(sessionARefreshToken)
    }

    _ = await refreshAStarted.first(where: { _ in true })
    await sut.update(recoverySessionB)

    let refreshB = Task {
      try await sut.refreshSession(sessionBRefreshToken)
    }
    let secondRefreshB = Task {
      try await sut.refreshSession(sessionBRefreshToken)
    }

    releaseRefreshBContinuation.yield(())
    releaseRefreshBContinuation.finish()
    releaseRefreshAContinuation.yield(())
    releaseRefreshAContinuation.finish()

    let refreshAResult = await refreshA.result
    let refreshBResult = await refreshB.result
    let secondRefreshBResult = await secondRefreshB.result

    XCTAssertEqual(
      requestedTokens.value,
      [sessionARefreshToken, sessionBRefreshToken],
      "A replacement refresh must start its own operation and coalesce its second caller."
    )
    if case .success = refreshAResult {
      XCTFail("A stale refresh must not complete successfully after B replaced A.")
    }
    XCTAssertEqual(try refreshBResult.get().refreshToken, responseSessionB.refreshToken)
    XCTAssertEqual(try secondRefreshBResult.get().refreshToken, responseSessionB.refreshToken)
    XCTAssertEqual(
      Dependencies[clientID].sessionStorage.get()?.refreshToken,
      responseSessionB.refreshToken
    )
  }

  func testRefreshThatFinishesAfterRemovalDoesNotRestoreTheRemovedSession() async throws {
    let sessionA = Session.expiredSession
    Dependencies[clientID].sessionStorage.store(sessionA)

    let (refreshRequestStarted, refreshRequestStartedContinuation) = AsyncStream<Void>.makeStream()
    let (releaseRefreshResponse, releaseRefreshResponseContinuation) = AsyncStream<Void>.makeStream()

    await http.when(
      { $0.url.path.contains("/token") },
      return: { _ in
        refreshRequestStartedContinuation.yield(())
        _ = await releaseRefreshResponse.first(where: { _ in true })
        return .stub(Session.validSession)
      }
    )

    let events = LockIsolated([(AuthChangeEvent, Session?)]())
    let eventToken = Dependencies[clientID].eventEmitter.attach { event, session in
      events.withValue { $0.append((event, session)) }
    }
    defer { eventToken.cancel() }

    let refreshTask = Task {
      try await sut.refreshSession(sessionA.refreshToken)
    }

    _ = await refreshRequestStarted.first(where: { _ in true })
    await sut.remove()

    releaseRefreshResponseContinuation.yield(())
    releaseRefreshResponseContinuation.finish()

    let refreshResult = await refreshTask.result

    XCTAssertNil(Dependencies[clientID].sessionStorage.get())
    XCTAssertFalse(events.value.contains { $0.0 == .tokenRefreshed })
    if case .success = refreshResult {
      XCTFail("A refresh that outlives session removal must not restore that session.")
    }
  }

  func testConcurrentCurrentRefreshesStillCoalesce() async throws {
    let currentSession = Session.expiredSession
    let refreshedSession = Session.validSession
    Dependencies[clientID].sessionStorage.store(currentSession)

    let requestCount = LockIsolated(0)
    let (refreshRequestStarted, refreshRequestStartedContinuation) = AsyncStream<Void>.makeStream()
    let (releaseRefreshResponse, releaseRefreshResponseContinuation) = AsyncStream<Void>.makeStream()

    await http.when(
      { $0.url.path.contains("/token") },
      return: { _ in
        requestCount.withValue { $0 += 1 }
        refreshRequestStartedContinuation.yield(())
        _ = await releaseRefreshResponse.first(where: { _ in true })
        return .stub(refreshedSession)
      }
    )

    let firstRefresh = Task {
      try await sut.refreshSession(currentSession.refreshToken)
    }
    _ = await refreshRequestStarted.first(where: { _ in true })
    let secondRefresh = Task {
      try await sut.refreshSession(currentSession.refreshToken)
    }

    releaseRefreshResponseContinuation.yield(())
    releaseRefreshResponseContinuation.finish()

    let firstResult = try await firstRefresh.value
    let secondResult = try await secondRefresh.value

    XCTAssertEqual(firstResult.refreshToken, refreshedSession.refreshToken)
    XCTAssertEqual(secondResult.refreshToken, refreshedSession.refreshToken)
    XCTAssertEqual(requestCount.value, 1)
  }
}

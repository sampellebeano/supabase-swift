import Foundation

struct SessionManager: Sendable {
  var session: @Sendable () async throws -> Session
  var refreshSession: @Sendable (_ refreshToken: String) async throws -> Session
  var refreshCurrentSession: @Sendable () async throws -> Session
  var refreshCurrentSessionIfExpired: @Sendable () async -> Void
  var update: @Sendable (_ session: Session) async -> Void
  var updateUser: @Sendable (_ session: Session) async -> Void
  var remove: @Sendable () async -> Void

  var startAutoRefresh: @Sendable () async -> Void
  var stopAutoRefresh: @Sendable () async -> Void
}

extension SessionManager {
  static func live(clientID: AuthClientID) -> Self {
    let instance = LiveSessionManager(clientID: clientID)
    return Self(
      session: { try await instance.session() },
      refreshSession: { try await instance.refreshSession($0) },
      refreshCurrentSession: { try await instance.refreshCurrentSession() },
      refreshCurrentSessionIfExpired: { await instance.refreshCurrentSessionIfExpired() },
      update: { await instance.update($0) },
      updateUser: { await instance.updateUser($0) },
      remove: { await instance.remove() },
      startAutoRefresh: { await instance.startAutoRefreshToken() },
      stopAutoRefresh: { await instance.stopAutoRefreshToken() }
    )
  }
}

private actor LiveSessionManager {
  private var configuration: AuthClient.Configuration { Dependencies[clientID].configuration }
  private var sessionStorage: SessionStorage { Dependencies[clientID].sessionStorage }
  private var eventEmitter: AuthStateChangeEventEmitter { Dependencies[clientID].eventEmitter }
  private var logger: (any SupabaseLogger)? { Dependencies[clientID].logger }
  private var api: APIClient { Dependencies[clientID].api }

  // A replacement/removal invalidates all work captured at an earlier epoch.
  // Only the current (epoch, operationID) may commit refresh side effects.
  // A defer clears the in-flight slot only when it still owns that slot.
  private var sessionEpoch: UInt64 = 0
  private var inFlightRefresh: RefreshOperation?
  private var startAutoRefreshTokenTask: Task<Void, Never>?

  let clientID: AuthClientID

  init(clientID: AuthClientID) {
    self.clientID = clientID
  }

  private struct RefreshOperation {
    let operationID: UUID
    let epoch: UInt64
    let refreshToken: String
    let task: Task<Session, any Error>
  }

  func session() async throws -> Session {
    try await trace(using: logger) {
      guard let currentSession = sessionStorage.get() else {
        logger?.debug("session missing")
        throw AuthError.sessionMissing
      }

      if !currentSession.isExpired {
        return currentSession
      }

      logger?.debug("session expired")
      return try await refreshSession(currentSession.refreshToken)
    }
  }

  func refreshSession(_ refreshToken: String) async throws -> Session {
    try await SupabaseLoggerTaskLocal.$additionalContext.withValue(
      merging: [
        "refresh_id": .string(UUID().uuidString),
        "refresh_token": .string(refreshToken),
      ]
    ) {
      try await trace(using: logger) {
        if let inFlightRefresh,
          inFlightRefresh.epoch == sessionEpoch,
          inFlightRefresh.refreshToken == refreshToken
        {
          logger?.debug("Refresh already in flight")
          return try await inFlightRefresh.task.value
        }

        let operationID = UUID()
        let epoch = sessionEpoch
        let refreshTask = Task {
          logger?.debug("Refresh task started")

          defer {
            clearRefreshOperationIfOwned(operationID: operationID, epoch: epoch)
            logger?.debug("Refresh task ended")
          }

          do {
            let session = try await api.execute(
              HTTPRequest(
                url: configuration.url.appendingPathComponent("token"),
                method: .post,
                query: [
                  URLQueryItem(name: "grant_type", value: "refresh_token")
                ],
                body: configuration.encoder.encode(
                  UserCredentials(refreshToken: refreshToken)
                )
              ),
              sessionCleanupPolicy: .refreshOwner
            )
            .decoded(as: Session.self, decoder: configuration.decoder)

            return try commitRefresh(
              session,
              operationID: operationID,
              epoch: epoch
            )
          } catch {
            return try resolveRefreshFailure(
              error,
              operationID: operationID,
              epoch: epoch
            )
          }
        }

        inFlightRefresh = RefreshOperation(
          operationID: operationID,
          epoch: epoch,
          refreshToken: refreshToken,
          task: refreshTask
        )

        return try await refreshTask.value
      }
    }
  }

  func refreshCurrentSession() async throws -> Session {
    guard let currentSession = sessionStorage.get() else {
      throw AuthError.sessionMissing
    }

    return try await refreshSession(currentSession.refreshToken)
  }

  func refreshCurrentSessionIfExpired() async {
    guard let currentSession = sessionStorage.get(), currentSession.isExpired else {
      return
    }

    _ = try? await refreshSession(currentSession.refreshToken)
  }

  func update(_ session: Session) {
    invalidateRefreshOperations()
    sessionStorage.store(session)
  }

  func updateUser(_ session: Session) {
    sessionStorage.store(session)
  }

  func remove() {
    invalidateRefreshOperations()
    sessionStorage.delete()
  }

  func startAutoRefreshToken() {
    logger?.debug("start auto refresh token")

    startAutoRefreshTokenTask?.cancel()
    startAutoRefreshTokenTask = Task {
      while !Task.isCancelled {
        await autoRefreshTokenTick()
        try? await Task.sleep(nanoseconds: NSEC_PER_SEC * UInt64(autoRefreshTickDuration))
      }
    }
  }

  func stopAutoRefreshToken() {
    logger?.debug("stop auto refresh token")
    startAutoRefreshTokenTask?.cancel()
    startAutoRefreshTokenTask = nil
  }

  private func autoRefreshTokenTick() async {
    await trace(using: logger) {
      let now = Date().timeIntervalSince1970

      guard let session = sessionStorage.get() else {
        return
      }

      let expiresInTicks = Int((session.expiresAt - now) / autoRefreshTickDuration)
      logger?.debug(
        "access token expires in \(expiresInTicks) ticks, a tick lasts \(autoRefreshTickDuration)s, refresh threshold is \(autoRefreshTickThreshold) ticks"
      )

      if expiresInTicks <= autoRefreshTickThreshold {
        _ = try? await refreshSession(session.refreshToken)
      }
    }
  }

  private func commitRefresh(
    _ session: Session,
    operationID: UUID,
    epoch: UInt64
  ) throws -> Session {
    guard ownsRefreshOperation(operationID: operationID, epoch: epoch) else {
      throw CancellationError()
    }

    sessionStorage.store(session)
    eventEmitter.emit(.tokenRefreshed, session: session)
    return session
  }

  private func resolveRefreshFailure(
    _ error: any Error,
    operationID: UUID,
    epoch: UInt64
  ) throws -> Session {
    guard ownsRefreshOperation(operationID: operationID, epoch: epoch) else {
      throw CancellationError()
    }

    guard error as? AuthError == .sessionMissing else {
      throw error
    }

    invalidateRefreshOperations()
    sessionStorage.delete()
    eventEmitter.emit(.signedOut, session: nil)
    throw error
  }

  private func ownsRefreshOperation(operationID: UUID, epoch: UInt64) -> Bool {
    guard sessionEpoch == epoch, let inFlightRefresh else {
      return false
    }

    return inFlightRefresh.operationID == operationID && inFlightRefresh.epoch == epoch
  }

  private func clearRefreshOperationIfOwned(operationID: UUID, epoch: UInt64) {
    guard ownsRefreshOperation(operationID: operationID, epoch: epoch) else {
      return
    }

    inFlightRefresh = nil
  }

  private func invalidateRefreshOperations() {
    sessionEpoch &+= 1
    inFlightRefresh = nil
  }
}

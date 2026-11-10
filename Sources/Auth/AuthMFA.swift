import Foundation

/// Contains the full multi-factor authentication API.
public struct AuthMFA: Sendable {
  /// An opaque reference to the session installed by a successful MFA verification.
  public struct VerifiedSession: Sendable {
    fileprivate let clientID: AuthClientID
    fileprivate let context: SessionMutationContext
  }

  let clientID: AuthClientID

  var configuration: AuthClient.Configuration { Dependencies[clientID].configuration }
  var api: APIClient { Dependencies[clientID].api }
  var encoder: JSONEncoder { Dependencies[clientID].encoder }
  var decoder: JSONDecoder { Dependencies[clientID].decoder }
  var sessionManager: SessionManager { Dependencies[clientID].sessionManager }

  /// Starts the enrollment process for a new Multi-Factor Authentication (MFA) factor. This method
  /// creates a new `unverified` factor.
  /// To verify a factor, present the QR code or secret to the user and ask them to add it to their
  /// authenticator app.
  /// The user has to enter the code from their authenticator app to verify it.
  ///
  /// Upon verifying a factor, all other sessions are logged out and the current session's
  /// authenticator level is promoted to `aal2`.
  ///
  /// - Parameter params: The parameters for enrolling a new MFA factor.
  /// - Returns: An authentication response after enrolling the factor.
  public func enroll(params: any MFAEnrollParamsType) async throws -> AuthMFAEnrollResponse {
    try await api.authorizedExecute(
      HTTPRequest(
        url: configuration.url.appendingPathComponent("factors"),
        method: .post,
        body: encoder.encode(params)
      )
    )
    .decoded(decoder: decoder)
  }

  /// Prepares a challenge used to verify that a user has access to a MFA factor.
  ///
  /// - Parameter params: The parameters for creating a challenge.
  /// - Returns: An authentication response with the challenge information.
  public func challenge(params: MFAChallengeParams) async throws -> AuthMFAChallengeResponse {
    let context = try await sessionManager.mfaContext()
    return try await challenge(params: params, context: context)
  }

  private func challenge(
    params: MFAChallengeParams,
    context: SessionMutationContext
  ) async throws -> AuthMFAChallengeResponse {
    try await execute(
      HTTPRequest(
        url: configuration.url.appendingPathComponent("factors/\(params.factorId)/challenge"),
        method: .post,
        body: params.channel == nil ? nil : encoder.encode(["channel": params.channel])
      ),
      context: context
    )
    .decoded(decoder: decoder)
  }

  /// Verifies a code against a challenge. The verification code is
  /// provided by the user by entering a code seen in their authenticator app.
  ///
  /// - Parameter params: The parameters for verifying the MFA factor.
  /// - Returns: An authentication response after verifying the factor.
  @discardableResult
  public func verify(params: MFAVerifyParams) async throws -> AuthMFAVerifyResponse {
    let context = try await sessionManager.mfaContext()
    return try await verify(params: params, context: context).session
  }

  private func verify(
    params: MFAVerifyParams,
    context: SessionMutationContext
  ) async throws -> SessionMutationContext {
    let response: AuthMFAVerifyResponse = try await execute(
      HTTPRequest(
        url: configuration.url.appendingPathComponent("factors/\(params.factorId)/verify"),
        method: .post,
        body: encoder.encode(params)
      ),
      context: context
    ).decoded(decoder: decoder)

    return try await sessionManager.commitMFAVerification(response, context)
  }

  private func execute(_ request: HTTPRequest, context: SessionMutationContext) async throws
    -> HTTPResponse
  {
    let requestContext = try await sessionManager.mfaRequestContext(context)
    var request = request
    request.headers[.authorization] = "Bearer \(requestContext.session.accessToken)"
    let response: HTTPResponse
    do {
      response = try await api.execute(request, sessionCleanupPolicy: .deferredToSessionOwner)
    } catch {
      try await sessionManager.requireMFAContext(context)
      if error as? AuthError == .sessionMissing {
        _ = await sessionManager.removeIfMutationOwned(requestContext)
      }
      throw error
    }
    try await sessionManager.requireMFAContext(context)
    return response
  }

  /// Unenroll removes a MFA factor.
  /// A user has to have an `aal2` authenticator level in order to unenroll a `verified` factor.
  ///
  /// - Parameter params: The parameters for unenrolling an MFA factor.
  /// - Returns: An authentication response after unenrolling the factor.
  @discardableResult
  public func unenroll(params: MFAUnenrollParams) async throws -> AuthMFAUnenrollResponse {
    try await api.authorizedExecute(
      HTTPRequest(
        url: configuration.url.appendingPathComponent("factors/\(params.factorId)"),
        method: .delete
      )
    )
    .decoded(decoder: decoder)
  }

  /// Helper method which creates a challenge and immediately uses the given code to verify against
  /// it thereafter. The verification code is
  /// provided by the user by entering a code seen in their authenticator app.
  ///
  /// - Parameter params: The parameters for creating and verifying a challenge.
  /// - Returns: An authentication response after verifying the challenge.
  @discardableResult
  public func challengeAndVerify(
    params: MFAChallengeAndVerifyParams
  ) async throws -> AuthMFAVerifyResponse {
    try await challengeAndVerifyForRefresh(params: params).context.session
  }

  /// Challenges and verifies a factor, returning a reference for a forced refresh of the
  /// verified session. The reference becomes invalid when the session is replaced or removed.
  public func challengeAndVerifyForRefresh(
    params: MFAChallengeAndVerifyParams
  ) async throws -> VerifiedSession {
    let context = try await sessionManager.mfaContext()
    let response = try await challenge(
      params: MFAChallengeParams(factorId: params.factorId),
      context: context
    )
    let verified = try await verify(
      params: MFAVerifyParams(
        factorId: params.factorId, challengeId: response.id, code: params.code
      ),
      context: context
    )
    return VerifiedSession(clientID: clientID, context: verified)
  }

  /// Forces a refresh for the verified session and reports assurance from that refresh response.
  /// Throws `CancellationError` if the reference belongs to another client or a replaced session.
  public func refreshVerifiedSession(
    _ verification: VerifiedSession
  ) async throws -> AuthMFAGetAuthenticatorAssuranceLevelResponse {
    guard verification.clientID == clientID else { throw CancellationError() }
    let session = try await sessionManager.refreshVerifiedMFASession(verification.context)
    return assurance(for: session)
  }

  /// Returns the list of MFA factors enabled for this user.
  ///
  /// - Returns: An authentication response with the list of MFA factors.
  public func listFactors() async throws -> AuthMFAListFactorsResponse {
    let user = try await sessionManager.session().user
    let factors = user.factors ?? []
    let totp = factors.filter {
      $0.factorType == "totp" && $0.status == .verified
    }
    let phone = factors.filter {
      $0.factorType == "phone" && $0.status == .verified
    }
    return AuthMFAListFactorsResponse(all: factors, totp: totp, phone: phone)
  }

  /// Returns the Authenticator Assurance Level (AAL) for the active session.
  ///
  /// - Returns: An authentication response with the Authenticator Assurance Level.
  public func getAuthenticatorAssuranceLevel() async throws
    -> AuthMFAGetAuthenticatorAssuranceLevelResponse
  {
    do {
      return assurance(for: try await sessionManager.session())
    } catch AuthError.sessionMissing {
      return AuthMFAGetAuthenticatorAssuranceLevelResponse(
        currentLevel: nil,
        nextLevel: nil,
        currentAuthenticationMethods: []
      )
    }
  }

  private func assurance(for session: Session) -> AuthMFAGetAuthenticatorAssuranceLevelResponse {
    let payload = JWT.decodePayload(session.accessToken)

    var currentLevel: AuthenticatorAssuranceLevels?

    if let aal = payload?["aal"] as? AuthenticatorAssuranceLevels {
      currentLevel = aal
    }

    var nextLevel = currentLevel

    let verifiedFactors = session.user.factors?.filter { $0.status == .verified } ?? []
    if !verifiedFactors.isEmpty {
      nextLevel = "aal2"
    }

    var currentAuthenticationMethods: [AMREntry] = []

    if let amr = payload?["amr"] as? [Any] {
      currentAuthenticationMethods = amr.compactMap(AMREntry.init(value:))
    }

    return AuthMFAGetAuthenticatorAssuranceLevelResponse(
      currentLevel: currentLevel,
      nextLevel: nextLevel,
      currentAuthenticationMethods: currentAuthenticationMethods
    )
  }
}

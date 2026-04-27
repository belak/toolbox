// Package auth provides session, API token, password, OIDC, and rate-
// limit primitives plus the middleware to wire them into an HTTP
// pipeline.
//
// # Concepts
//
// The pipeline is built from three layers:
//
//   - Managers ([SessionManager], [APITokenManager]) own storage and
//     crypto. They are constructed once at startup with a backing store.
//
//   - Resolvers ([Resolver]) extract an authenticated identity from a
//     request and stash it on the context. Built-in resolvers
//     ([SessionResolver], [BearerTokenResolver], [BasicAuthTokenResolver])
//     wrap the matching manager. [ChainResolvers] tries several in
//     order, first-match wins.
//
//   - Gates wrap resolvers in HTTP middleware. [Require] rejects
//     unauthenticated requests; [Optional] passes them through with no
//     identity attached. Layer [RequireKind] or [RequirePredicate] on
//     top to gate authenticated requests further.
//
// # Canonical wire-up
//
//	type sessionData struct{ /* ... */ }
//
//	type ctxKey struct{ name string }
//	var (
//		sessionKey = ctxKey{"session"}
//		tokenKey   = ctxKey{"token"}
//	)
//
//	func GetSession(ctx context.Context) *auth.Session[sessionData] {
//		s, _ := ctx.Value(sessionKey).(*auth.Session[sessionData])
//		return s
//	}
//	func GetToken(ctx context.Context) *auth.APIToken {
//		t, _ := ctx.Value(tokenKey).(*auth.APIToken)
//		return t
//	}
//
//	sessions := auth.NewSessionManager[sessionData](store)
//	tokens   := auth.NewAPITokenManager(tokens)
//
//	resolver := auth.ChainResolvers(
//		auth.SessionResolver(sessions, sessionKey),
//		auth.BearerTokenResolver(tokens, tokenKey),
//	)
//
//	requireAuth := auth.Require(resolver,
//		auth.OnUnauthorized(redirectToLogin),
//		auth.OnError(logAndFail),
//	)
//	router.Use(requireAuth)
//
//	// Session-only endpoint:
//	router.With(auth.RequireKind(nil, auth.KindSession)).Get("/admin", h)
//
//	// Custom predicate (e.g. admin role check):
//	isAdmin := func(r *http.Request) bool {
//		u := loadUser(r.Context())
//		return u != nil && u.IsAdmin
//	}
//	router.With(auth.RequirePredicate(isAdmin, nil)).Get("/users", h)
//
// # Custom resolvers
//
// Apps that need to JOIN session and user in a single query (or do any
// other custom loading) write their own [Resolver]: a function that
// returns the request context with values attached, an ok flag, and an
// error. Custom resolvers should call [WithKind] to stamp the auth
// kind so [RequireKind] works downstream.
package auth

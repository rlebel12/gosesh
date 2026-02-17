package gosesh

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// OAuth2Begin creates a handler that initiates the OAuth2 flow.
// It generates a secure state parameter, sets it in a cookie, and redirects to the OAuth2 provider.
func (gs *Gosesh) OAuth2Begin(oauthCfg *oauth2.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setSecureCookieHeaders(w)

		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			gs.logger.Error("create OAuth2 state", "error", err)
			http.Error(w, "create OAuth2 state", http.StatusInternalServerError)
			return
		}
		state := base64.URLEncoding.EncodeToString(b)

		expiration := gs.now().UTC().Add(5 * time.Minute)
		cookie := gs.oauthStateCookie(state, expiration)
		http.SetCookie(w, cookie)

		next := r.URL.Query().Get(gs.redirectParamName)
		if next != "" {
			gs.setRedirectCookie(next, w)
		}

		url := oauthCfg.AuthCodeURL(state)
		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	}
}

type (
	// HandlerDoneFunc is a function type that handles the completion of an OAuth2 flow.
	// It is called with the response writer, request, and any error that occurred.
	HandlerDoneFunc func(http.ResponseWriter, *http.Request, error)

	// RequestFunc is a function type that retrieves user data from an OAuth2 provider.
	// It takes a context and access token, and returns a reader with the user data.
	RequestFunc func(ctx context.Context, accessToken string) (io.ReadCloser, error)

	// UnmarshalFunc is a function type that unmarshals user data into an auth provider ID.
	// It takes the raw user data and returns an AuthProviderID and any error that occurred.
	UnmarshalFunc func(b []byte) (AuthProviderID, error)
)

// OAuth2Callback creates a handler that completes the OAuth2 flow.
// It validates the state parameter, exchanges the code for a token, retrieves user data,
// and creates a session. When complete, it calls the provided done handler.
func (gs *Gosesh) OAuth2Callback(config *oauth2.Config, request RequestFunc, unmarshal UnmarshalFunc, done HandlerDoneFunc) http.HandlerFunc {
	if done == nil {
		gs.logger.Warn("no done handler provided for OAuth2Callback, using default")
		done = defaultDoneHandler(gs, "OAuth2Callback")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		setSecureCookieHeaders(w)

		ctx := r.Context()
		oauthState, err := r.Cookie(gs.oAuth2StateCookieName)
		if err != nil {
			done(w, r, fmt.Errorf("%w: %w", ErrFailedGettingStateCookie, err))
			return
		}

		now := gs.now().UTC()
		stateCookie := gs.oauthStateCookie("", now)
		http.SetCookie(w, stateCookie)

		if r.FormValue("state") != oauthState.Value {
			done(w, r, ErrInvalidStateCookie)
			return
		}

		token, err := config.Exchange(ctx, r.FormValue("code"))
		if err != nil {
			done(w, r, fmt.Errorf("%w: %w", ErrFailedExchangingToken, err))
			return
		}

		user, err := unmarshalUserData(ctx, request, unmarshal, token.AccessToken)
		if err != nil {
			done(w, r, fmt.Errorf("%w: %w", ErrFailedUnmarshallingData, err))
			return
		}

		id, err := gs.store.UpsertUser(ctx, user)
		if err != nil {
			done(w, r, fmt.Errorf("%w: %w", ErrFailedUpsertingUser, err))
			return
		}

		// Generate raw session ID
		rawID, err := gs.idGenerator()
		if err != nil {
			done(w, r, fmt.Errorf("generate session ID: %w", err))
			return
		}

		// Hash the raw ID before storing
		hashedID := gs.idHasher(rawID)

		sessionCfg := gs.credentialSource.SessionConfig()
		session, err := gs.store.CreateSession(
			ctx, hashedID, id, now.Add(sessionCfg.IdleDuration), now.Add(sessionCfg.AbsoluteDuration))
		if err != nil {
			done(w, r, fmt.Errorf("%w: %w", ErrFailedCreatingSession, err))
			return
		}

		// Write raw ID to credential source (cookie/header)
		if err := gs.credentialSource.WriteSession(w, rawID, session); err != nil {
			done(w, r, fmt.Errorf("write session: %w", err))
			return
		}
		done(w, r, nil)
	}
}

// unmarshalUserData retrieves and unmarshals user data from an OAuth2 provider.
func unmarshalUserData(
	ctx context.Context,
	request RequestFunc,
	unmarshal UnmarshalFunc,
	accessToken string,
) (AuthProviderID, error) {
	response, err := request(ctx, accessToken)
	if err != nil {
		return nil, fmt.Errorf("get user info: %w", err)
	}
	defer response.Close()
	contents, err := io.ReadAll(response)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	user, err := unmarshal(contents)
	if err != nil {
		return nil, fmt.Errorf("unmarshal user data: %w", err)
	}
	return user, nil
}

// ExchangeTokenRequest is the expected JSON body for the token exchange endpoint.
type ExchangeTokenRequest struct {
	AccessToken string `json:"access_token"`
}

// ExchangeTokenResponse is the JSON response for the token exchange endpoint.
type ExchangeTokenResponse struct {
	SessionID string    `json:"session_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ExchangeExternalToken creates a handler that exchanges an external OAuth2 access token
// for a gosesh session. This is used by native app clients (desktop, mobile, CLI) that
// handle OAuth2/PKCE directly with the identity provider and then exchange the access
// token for a session. Uses native app session config (30-day absolute timeout, no idle timeout).
func (gs *Gosesh) ExchangeExternalToken(
	request RequestFunc,
	unmarshal UnmarshalFunc,
	done HandlerDoneFunc,
	opts ...ExchangeOption,
) http.HandlerFunc {
	if done == nil {
		gs.logger.Warn("no done handler provided for ExchangeExternalToken, using default")
		done = defaultExchangeTokenDoneHandler(gs)
	}

	// Apply options to config at construction time
	cfg := &exchangeConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		var req ExchangeTokenRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			done(w, r, fmt.Errorf("parse request body: %w", err))
			return
		}

		if req.AccessToken == "" {
			done(w, r, errors.New("validate token: empty access_token"))
			return
		}

		// Audience validation block
		if cfg.audienceValidator != nil {
			// Call validator with request context.
			// The validator implementation is responsible for timeout handling.
			// Context cancellation/deadline from r.Context() propagates to validator.
			audience, err := cfg.audienceValidator.ValidateAudience(ctx, req.AccessToken)
			if err != nil {
				// Wrap validator error with sentinel.
				// This enables: errors.Is(err, ErrFailedValidatingAudience) == true
				// The underlying error (network, timeout, etc.) is preserved in the chain.
				done(w, r, fmt.Errorf("%w: %w", ErrFailedValidatingAudience, err))
				return
			}

			// Check against expected audiences (only if non-empty - permissive behavior per Decision 5)
			if len(cfg.expectedAudiences) > 0 {
				if !slices.Contains(cfg.expectedAudiences, audience) {
					// Create structured error with context, wrapped with sentinel.
					// This enables both:
					//   errors.Is(err, ErrFailedValidatingAudience) == true
					//   errors.As(err, &audErr) == true (extracts AudienceValidationError)
					err := &AudienceValidationError{
						Expected: cfg.expectedAudiences,
						Actual:   audience,
					}
					done(w, r, fmt.Errorf("%w: %w", ErrFailedValidatingAudience, err))
					return
				}
			}
		}

		user, err := fetchAndUnmarshalUserData(ctx, request, unmarshal, req.AccessToken)
		if err != nil {
			done(w, r, err)
			return
		}

		userID, err := gs.store.UpsertUser(ctx, user)
		if err != nil {
			done(w, r, fmt.Errorf("%w: %w", ErrFailedUpsertingUser, err))
			return
		}

		// Generate raw session ID
		rawID, err := gs.idGenerator()
		if err != nil {
			done(w, r, fmt.Errorf("generate session ID: %w", err))
			return
		}

		// Hash the raw ID before storing
		hashedID := gs.idHasher(rawID)

		now := gs.now().UTC()
		nativeAppConfig := DefaultNativeAppSessionConfig()
		session, err := gs.store.CreateSession(
			ctx,
			hashedID,
			userID,
			now.Add(nativeAppConfig.IdleDuration),
			now.Add(nativeAppConfig.AbsoluteDuration),
		)
		if err != nil {
			done(w, r, fmt.Errorf("%w: %w", ErrFailedCreatingSession, err))
			return
		}

		response := ExchangeTokenResponse{
			SessionID: string(rawID), // Return raw ID in JSON, not hashed
			ExpiresAt: session.AbsoluteDeadline(),
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			done(w, r, fmt.Errorf("encode response: %w", err))
			return
		}
		done(w, r, nil)
	}
}

// fetchAndUnmarshalUserData retrieves and unmarshals user data from an OAuth2 provider.
// Unlike unmarshalUserData, this function wraps errors with appropriate sentinel types
// for the ExchangeExternalToken handler.
func fetchAndUnmarshalUserData(
	ctx context.Context,
	request RequestFunc,
	unmarshal UnmarshalFunc,
	accessToken string,
) (AuthProviderID, error) {
	response, err := request(ctx, accessToken)
	if err != nil {
		return nil, fmt.Errorf("%w: fetch user data: %w", ErrFailedExchangingToken, err)
	}
	defer response.Close()
	contents, err := io.ReadAll(response)
	if err != nil {
		return nil, fmt.Errorf("%w: read response: %w", ErrFailedExchangingToken, err)
	}
	user, err := unmarshal(contents)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFailedUnmarshallingData, err)
	}
	return user, nil
}

// defaultExchangeTokenDoneHandler creates a default handler for ExchangeExternalToken completion.
// It handles errors by setting appropriate HTTP status codes.
func defaultExchangeTokenDoneHandler(gs *Gosesh) HandlerDoneFunc {
	return func(w http.ResponseWriter, r *http.Request, err error) {
		if err != nil {
			code := http.StatusInternalServerError
			// Check for validation errors (should be 400)
			errMsg := err.Error()
			if strings.HasPrefix(errMsg, "parse request body:") ||
				strings.HasPrefix(errMsg, "validate token:") {
				code = http.StatusBadRequest
			}
			gs.logger.Error("exchange token", "error", err)
			http.Error(w, http.StatusText(code), code)
			return
		}
	}
}

var (
	ErrUnauthorized          = errors.New("unauthorized")
	ErrFailedDeletingSession = errors.New("failed deleting session(s)")
)

// Logout creates a handler that terminates a user's session.
// If the "all" query parameter is present, it terminates all sessions for the user.
func (gs *Gosesh) Logout(done HandlerDoneFunc) http.HandlerFunc {
	if done == nil {
		gs.logger.Warn("no done handler provided for Logout, using default")
		done = defaultDoneHandler(gs, "Logout")
	}
	return gs.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, ok := CurrentSession(r)
		if !ok {
			done(w, r, ErrUnauthorized)
			return
		}

		var err error
		switch {
		case r.URL.Query().Get("all") != "":
			_, err = gs.store.DeleteUserSessions(r.Context(), session.UserID())
		default:
			err = gs.store.DeleteSession(r.Context(), session.ID())
		}
		if err != nil {
			done(w, r, fmt.Errorf("%w: %w", ErrFailedDeletingSession, err))
			return
		}

		if err := gs.credentialSource.ClearSession(w); err != nil {
			done(w, r, fmt.Errorf("clear session: %w", err))
			return
		}
		ctx := context.WithValue(r.Context(), sessionKey, nil)
		done(w, r.WithContext(ctx), nil)
	})).ServeHTTP
}

// CallbackRedirect creates a handler that redirects after an OAuth2 flow completes.
// It uses the redirect cookie to determine where to redirect, falling back to the default target.
func (gs *Gosesh) CallbackRedirect(defaultTarget string) http.HandlerFunc {
	if defaultTarget == "" {
		defaultTarget = "/"
	}
	return func(w http.ResponseWriter, r *http.Request) {
		redirectCookie, err := r.Cookie(gs.redirectCookieName)
		if err != nil {
			http.Redirect(w, r, defaultTarget, http.StatusTemporaryRedirect)
			return
		}

		path, err := base64.URLEncoding.DecodeString(redirectCookie.Value)
		redirectCookie = gs.redirectCookie("", gs.now())
		http.SetCookie(w, redirectCookie)
		if err != nil {
			gs.logger.Error("decode redirect path", "error", err)
			http.Redirect(w, r, defaultTarget, http.StatusTemporaryRedirect)
			return
		}

		url, err := url.Parse(string(path))
		if err != nil {
			gs.logger.Error("parse redirect path", "error", err)
			http.Redirect(w, r, defaultTarget, http.StatusTemporaryRedirect)
			return
		} else if url.Hostname() != "" && !slices.Contains(gs.allowedHosts, url.Hostname()) {
			gs.logger.Warn("disallowed host in redirect path", "host", url.Host)
			http.Redirect(w, r, defaultTarget, http.StatusTemporaryRedirect)
			return
		}

		http.Redirect(w, r, url.String(), http.StatusTemporaryRedirect)
	}
}

// defaultDoneHandler creates a default handler for OAuth2 flow completion.
// It handles errors by setting appropriate HTTP status codes and redirects on success.
func defaultDoneHandler(gs *Gosesh, handlerName string) HandlerDoneFunc {
	redirect := gs.CallbackRedirect("/")
	return func(w http.ResponseWriter, r *http.Request, err error) {
		if err != nil {
			code := http.StatusInternalServerError
			switch {
			case errors.Is(err, ErrUnauthorized):
				code = http.StatusUnauthorized
			case errors.Is(err, ErrSessionExpired):
				code = http.StatusUnauthorized
			default:
				gs.logger.Error("callback", "error", err, "name", handlerName)
			}
			http.Error(w, http.StatusText(code), code)
			return
		}
		redirect(w, r)
	}
}

// Package sureauth is the official Go client for the sureAuth hosted auth
// service. One-line integration: create the client from the environment
// (SUREAUTH_SERVER_URL + SUREAUTH_API_KEY) and call Auth/Register — the
// library handles API-key auth, project scoping, OTP challenges and token
// refresh. Credentials are never hardcoded in your app.
package sureauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Env var names for zero-config setup.
const (
	EnvServerURL = "SUREAUTH_SERVER_URL"
	EnvAPIKey    = "SUREAUTH_API_KEY"
)

// DefaultServerURL is used when the env var is absent.
const DefaultServerURL = "https://auth.sureauth.app"

// Challenge types returned by the server.
const (
	ChallengePhoneRequired    = "phone_required"
	ChallengeOTPRequired      = "otp_required"
	ChallengeMFARequired      = "mfa_required"
	ChallengeEmailVerifyRequired = "email_verify_required"
)

// Client talks to the sureAuth engine. Create with New() (env-driven) or
// NewWithConfig.
type Client struct {
	ServerURL string
	APIKey    string
	HTTP      *http.Client
	settings  *ProjectSettings // cached per-project settings
}

// Config holds explicit client configuration.
type Config struct {
	ServerURL string
	APIKey    string
	HTTPClient *http.Client
}

// New builds a client from the environment.
func New() (*Client, error) {
	serverURL := os.Getenv(EnvServerURL)
	if serverURL == "" {
		serverURL = DefaultServerURL
	}
	apiKey := os.Getenv(EnvAPIKey)
	if apiKey == "" {
		return nil, fmt.Errorf("sureauth: %s is required", EnvAPIKey)
	}
	return &Client{ServerURL: strings.TrimRight(serverURL, "/"), APIKey: apiKey, HTTP: &http.Client{Timeout: 30 * time.Second}}, nil
}

// NewWithConfig builds a client with explicit config.
func NewWithConfig(cfg Config) *Client {
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{ServerURL: strings.TrimRight(cfg.ServerURL, "/"), APIKey: cfg.APIKey, HTTP: cfg.HTTPClient}
}

// NewWithDefaults is an alias of New (kept for compatibility).
func NewWithDefaults() (*Client, error) { return New() }

// ---------------------------------------------------------------------------
// Request/response types (mirror the engine API)
// ---------------------------------------------------------------------------

// User is the end-user shape returned by the API.
type User struct {
	ID         string `json:"id"`
	Username   string `json:"username"`
	Email      string `json:"email"`
	Phone      string `json:"phone"`
	IsActive   bool   `json:"is_active"`
	IsVerified bool   `json:"is_verified"`
	Metadata   string `json:"metadata,omitempty"`
}

// Challenge is a next-step prompt from the server.
type Challenge struct {
	Type         string   `json:"type"`
	Field        string   `json:"field,omitempty"`
	Hint         string   `json:"hint,omitempty"`
	Fields       []string `json:"fields,omitempty"`
	ExistingApps []string `json:"existing_apps,omitempty"`
}

// AuthResult is the normalized auth outcome (tokens or challenges).
type AuthResult struct {
	User         *User       `json:"user,omitempty"`
	AccessToken  string      `json:"access_token,omitempty"`
	RefreshToken string      `json:"refresh_token,omitempty"`
	ExpiresIn    int64       `json:"expires_in,omitempty"`
	TokenType    string      `json:"token_type,omitempty"`
	Challenges   []Challenge `json:"challenges,omitempty"`
}

// AuthRequest is the register/login input.
type AuthRequest struct {
	Identifier string `json:"identifier,omitempty"`
	Credential string `json:"credential,omitempty"`

	// Register fields (per project settings).
	Email    string `json:"email,omitempty"`
	Phone    string `json:"phone,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	PIN      string `json:"pin,omitempty"`
	OTPCode  string `json:"otp_code,omitempty"`
	Metadata string `json:"metadata,omitempty"`
}
// SendOTPRequest asks the engine to deliver a metered OTP.
type SendOTPRequest struct {
	Identifier string `json:"identifier,omitempty"`
	Channel    string `json:"channel,omitempty"` // email | phone
	Purpose    string `json:"purpose,omitempty"` // login | register | verify | complete_phone
}

// SendOTPResponse reports the delivery result.
type SendOTPResponse struct {
	MessageID string `json:"message_id"`
	Channel   string `json:"channel"`
	ExpiresIn int64  `json:"expires_in"`
	Cost      int64  `json:"cost"`
	Currency  string `json:"currency"`
}

// VerifyOTPRequest completes an OTP flow.
type VerifyOTPRequest struct {
	Identifier string `json:"identifier"`
	Code       string `json:"code"`
}

// CompletePhoneRequest finishes a phone_required challenge.
type CompletePhoneRequest struct {
	Email   string `json:"email,omitempty"`
	Phone   string `json:"phone,omitempty"`
	OTPCode string `json:"otp_code,omitempty"`
}

// ProjectSettings mirrors the engine's per-project login settings.
type ProjectSettings struct {
	ProjectID         string   `json:"ProjectID"`
	IdentifierType    string   `json:"IdentifierType"`
	CredentialType    string   `json:"CredentialType"`
	PinLength         int      `json:"PinLength"`
	OTPChannel        string   `json:"OTPChannel"`
	AllowRegistration bool     `json:"AllowRegistration"`
	AllowGoogleSSO    bool     `json:"AllowGoogleSSO"`
	CallbackURLs      []string `json:"CallbackURLs"`
}

// Claims are the validated JWT claims from /me or /validate.
type Claims struct {
	AppUserID  string `json:"app_user_id"`
	ProjectID  string `json:"project_id"`
	IdentityID string `json:"identity_id"`
	Email      string `json:"email"`
	Username   string `json:"username"`
	Phone      string `json:"phone"`
	Type       string `json:"type"`
	Exp        int64  `json:"exp"`
}

// APIError is a typed API error.
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Status  int
}

func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("sureauth: %s: %s", e.Code, e.Message)
	}
	return fmt.Sprintf("sureauth: request failed (status %d)", e.Status)
}

// ---------------------------------------------------------------------------
// HTTP plumbing
// ---------------------------------------------------------------------------

type envelope struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data"`
	Error   *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func (c *Client) do(ctx context.Context, method, path string, body interface{}, out interface{}) error {
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.ServerURL+path, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", c.APIKey)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var env envelope
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &env); err != nil {
			return fmt.Errorf("sureauth: decode response: %w", err)
		}
	}
	if resp.StatusCode >= 400 || env.Error != nil {
		apiErr := &APIError{Status: resp.StatusCode}
		if env.Error != nil {
			apiErr.Code = env.Error.Code
			apiErr.Message = env.Error.Message
		}
		return apiErr
	}
	if out != nil && env.Data != nil {
		data, _ := json.Marshal(env.Data)
		return json.Unmarshal(data, out)
	}
	return nil
}

// ---------------------------------------------------------------------------
// One-line API
// ---------------------------------------------------------------------------

// Auth signs in an end user with the project's configured login method
// (identifier + credential). If the server needs more steps, the returned
// AuthResult carries Challenges — complete them with SendOTP/VerifyOTP/
// CompletePhone.
func (c *Client) Auth(ctx context.Context, identifier, credential string) (*AuthResult, error) {
	return c.Login(ctx, identifier, credential)
}

// Register creates an end user with the fields the project settings require.
func (c *Client) Register(ctx context.Context, req AuthRequest) (*AuthResult, error) {
	var out AuthResult
	if err := c.do(ctx, http.MethodPost, "/api/v1/auth/register", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Login authenticates an end user.
func (c *Client) Login(ctx context.Context, identifier, credential string) (*AuthResult, error) {
	var out AuthResult
	if err := c.do(ctx, http.MethodPost, "/api/v1/auth/login", AuthRequest{Identifier: identifier, Credential: credential}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// SendOTP requests a metered OTP delivery.
func (c *Client) SendOTP(ctx context.Context, req SendOTPRequest) (*SendOTPResponse, error) {
	var out SendOTPResponse
	if err := c.do(ctx, http.MethodPost, "/api/v1/auth/otp/send", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// VerifyOTP completes an OTP flow and returns tokens (or the next challenge).
func (c *Client) VerifyOTP(ctx context.Context, identifier, code string) (*AuthResult, error) {
	var out AuthResult
	if err := c.do(ctx, http.MethodPost, "/api/v1/auth/otp/verify", VerifyOTPRequest{Identifier: identifier, Code: code}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CompletePhone finishes a phone_required challenge.
func (c *Client) CompletePhone(ctx context.Context, req CompletePhoneRequest) (*AuthResult, error) {
	var out AuthResult
	if err := c.do(ctx, http.MethodPost, "/api/v1/auth/complete-phone", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Settings returns the project's login configuration (cached).
func (c *Client) Settings(ctx context.Context) (*ProjectSettings, error) {
	if c.settings != nil {
		return c.settings, nil
	}
	var out ProjectSettings
	if err := c.do(ctx, http.MethodGet, "/api/v1/projects/settings", nil, &out); err != nil {
		return nil, err
	}
	c.settings = &out
	return &out, nil
}

// LoginURL returns the hosted login page URL for the popup/redirect flow.
// The app redirects the browser there; after sign-in the engine redirects to
// the app's callback URL with ?code=... — complete it with CompleteLogin.
func (c *Client) LoginURL(ctx context.Context, redirectURI string) (string, error) {
	settings, err := c.Settings(ctx)
	if err != nil {
		return "", err
	}
	params := url.Values{}
	params.Set("client_id", settings.ProjectID)
	if redirectURI != "" {
		params.Set("redirect_uri", redirectURI)
	}
	return c.ServerURL + "/oauth/authorize?" + params.Encode(), nil
}

// CompleteLogin exchanges an authorization code (from the hosted flow
// callback) for tokens.
func (c *Client) CompleteLogin(ctx context.Context, code, redirectURI string) (*AuthResult, error) {
	settings, err := c.Settings(ctx)
	if err != nil {
		return nil, err
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", settings.ProjectID)
	form.Set("client_secret", c.APIKey)
	return c.tokenRequest(ctx, form)
}

// tokenRequest posts form data to /oauth/token (Bearer-style client auth is
// handled by the client_secret field).
func (c *Client) tokenRequest(ctx context.Context, form url.Values) (*AuthResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.ServerURL+"/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-API-Key", c.APIKey)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		var e struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		_ = json.Unmarshal(raw, &e)
		return nil, &APIError{Code: e.Error, Message: e.ErrorDescription, Status: resp.StatusCode}
	}
	var out AuthResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Me returns the claims for an access token.
func (c *Client) Me(ctx context.Context, accessToken string) (*Claims, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.ServerURL+"/api/v1/auth/me", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("X-API-Key", c.APIKey)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, err
	}
	if env.Error != nil {
		return nil, &APIError{Code: env.Error.Code, Message: env.Error.Message, Status: resp.StatusCode}
	}
	data, _ := json.Marshal(env.Data)
	var claims Claims
	if err := json.Unmarshal(data, &claims); err != nil {
		return nil, err
	}
	return &claims, nil
}

// ValidateToken validates a token with the engine.
func (c *Client) ValidateToken(ctx context.Context, token string) (*Claims, error) {
	var out struct {
		Valid  bool   `json:"valid"`
		Claims Claims `json:"claims"`
	}
	if err := c.do(ctx, http.MethodPost, "/api/v1/auth/validate", map[string]string{"token": token}, &out); err != nil {
		return nil, err
	}
	if !out.Valid {
		return nil, &APIError{Code: "INVALID_TOKEN", Message: "token invalid", Status: 401}
	}
	return &out.Claims, nil
}

// RefreshToken exchanges a refresh token for a new access token.
func (c *Client) RefreshToken(ctx context.Context, refreshToken string) (string, error) {
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := c.do(ctx, http.MethodPost, "/api/v1/auth/refresh", map[string]string{"refresh_token": refreshToken}, &out); err != nil {
		return "", err
	}
	return out.AccessToken, nil
}

// Logout invalidates the session for an access token.
func (c *Client) Logout(ctx context.Context, accessToken string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.ServerURL+"/api/v1/auth/logout", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("X-API-Key", c.APIKey)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return &APIError{Status: resp.StatusCode}
	}
	return nil
}

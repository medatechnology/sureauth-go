package sureauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// Challenge types returned by the server (account-management additions).
const (
	ChallengeFieldsRequired    = "fields_required"
	ChallengeLinkConsentRequired = "link_consent_required"
)

// ForgotRequest starts a password reset (OTP or email magic link).
type ForgotRequest struct {
	Identifier string `json:"identifier"`
	Channel    string `json:"channel,omitempty"` // "otp" (default) | "magic_link"
}

// ForgotResponse reports where the reset step was delivered.
type ForgotResponse struct {
	DeliveredTo string `json:"delivered_to"`
	Channel     string `json:"channel"`
	ExpiresIn   int64  `json:"expires_in"`
}

// ResetRequest completes a reset with the OTP code or the magic-link token.
type ResetRequest struct {
	Identifier  string `json:"identifier"`
	Code        string `json:"code,omitempty"`
	Token       string `json:"token,omitempty"`
	NewPassword string `json:"new_password"`
}

// ChangePasswordRequest sets a new password (current required when one exists).
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password,omitempty"`
	NewPassword     string `json:"new_password"`
}

// ChangeIdentifierRequest verifies and updates the identity's email or phone.
type ChangeIdentifierRequest struct {
	NewEmail string `json:"new_email,omitempty"`
	NewPhone string `json:"new_phone,omitempty"`
	OTPCode  string `json:"otp_code,omitempty"`
}

// UnlinkGoogleRequest removes the Google link (a new password is required
// when the account has none).
type UnlinkGoogleRequest struct {
	NewPassword string `json:"new_password,omitempty"`
}

// CompleteMembershipRequest finishes a fields_required challenge.
type CompleteMembershipRequest struct {
	Email    string `json:"email,omitempty"`
	Phone    string `json:"phone,omitempty"`
	Username string `json:"username,omitempty"`
	PIN      string `json:"pin,omitempty"`
	Password string `json:"password,omitempty"`
	OTPCode  string `json:"otp_code,omitempty"`
}

// ConfirmLinkRequest consents to linking Google to an existing identity.
type ConfirmLinkRequest struct {
	Email   string `json:"email"`
	OTPCode string `json:"otp_code"`
}

// ConfirmMergeRequest consents to merging membership with an existing golden copy identity.
type ConfirmMergeRequest struct {
	Identifier string `json:"identifier"`
	OTPCode    string `json:"otp_code"`
	AppUserID  string `json:"app_user_id,omitempty"`
}

// doAuthed sends a request with the end-user access token (Bearer) + API key.
func (c *Client) doAuthed(ctx context.Context, method, path, accessToken string, body interface{}, out interface{}) error {
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
	req.Header.Set("Authorization", "Bearer "+accessToken)

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

// Forgot starts a password reset (OTP or email magic link).
func (c *Client) Forgot(ctx context.Context, req ForgotRequest) (*ForgotResponse, error) {
	var out ForgotResponse
	if err := c.do(ctx, http.MethodPost, "/api/v1/auth/forgot", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Reset completes a password reset with the OTP code or magic-link token.
func (c *Client) Reset(ctx context.Context, req ResetRequest) error {
	return c.do(ctx, http.MethodPost, "/api/v1/auth/reset", req, nil)
}

// ChangePassword sets a new password for the authenticated user.
func (c *Client) ChangePassword(ctx context.Context, accessToken string, req ChangePasswordRequest) error {
	return c.doAuthed(ctx, http.MethodPost, "/api/v1/auth/change-password", accessToken, req, nil)
}

// ChangeIdentifier verifies and updates the identity's email or phone.
func (c *Client) ChangeIdentifier(ctx context.Context, accessToken string, req ChangeIdentifierRequest) error {
	return c.doAuthed(ctx, http.MethodPost, "/api/v1/auth/change-identifier", accessToken, req, nil)
}

// UnlinkGoogle removes the Google link (sets a password first when required).
func (c *Client) UnlinkGoogle(ctx context.Context, accessToken string, req UnlinkGoogleRequest) error {
	return c.doAuthed(ctx, http.MethodPost, "/api/v1/auth/unlink-google", accessToken, req, nil)
}

// LinkGoogle returns the SSO start URL for an explicit join.
func (c *Client) LinkGoogle(ctx context.Context, accessToken, redirectURI string) (string, error) {
	path := "/api/v1/auth/link-google"
	if redirectURI != "" {
		path += "?redirect=" + redirectURI
	}
	var out struct {
		URL string `json:"url"`
	}
	if err := c.doAuthed(ctx, http.MethodGet, path, accessToken, nil, &out); err != nil {
		return "", err
	}
	return out.URL, nil
}

// CompleteMembership finishes a fields_required challenge.
func (c *Client) CompleteMembership(ctx context.Context, req CompleteMembershipRequest) (*AuthResult, error) {
	var out AuthResult
	if err := c.do(ctx, http.MethodPost, "/api/v1/auth/complete-membership", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ConfirmLink consents to linking Google to an existing identity (OTP to the
// existing email).
func (c *Client) ConfirmLink(ctx context.Context, req ConfirmLinkRequest) (*AuthResult, error) {
	var out AuthResult
	if err := c.do(ctx, http.MethodPost, "/api/v1/auth/confirm-link", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ConfirmMerge finishes an identity_overlap_prompt challenge.
func (c *Client) ConfirmMerge(ctx context.Context, req ConfirmMergeRequest) (*AuthResult, error) {
	var out AuthResult
	if err := c.do(ctx, http.MethodPost, "/api/v1/auth/confirm-merge", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateMetadata updates custom metadata on the authenticated user.
func (c *Client) UpdateMetadata(ctx context.Context, accessToken string, metadata string) error {
	return c.doAuthed(ctx, http.MethodPatch, "/api/v1/auth/metadata", accessToken, map[string]string{"metadata": metadata}, nil)
}

# DATA — sureauth-go

## Exported interface

| Function / Method | Signature | Purpose |
|---|---|---|
| `New` | `func New() (*Client, error)` | Construct client from `SUREAUTH_SERVER_URL` + `SUREAUTH_API_KEY` |
| `NewWithConfig` | `func NewWithConfig(cfg Config) *Client` | Construct client with explicit config struct |
| `Client.Auth` | `(c *Client) Auth(ctx, identifier, credential string) (*AuthResult, error)` | Authenticate end user; alias of `Login` |
| `Client.Register` | `(c *Client) Register(ctx, req AuthRequest) (*AuthResult, error)` | Register new user per project settings |
| `Client.Login` | `(c *Client) Login(ctx, identifier, credential string) (*AuthResult, error)` | Sign in with identifier + credential |
| `Client.SendOTP` | `(c *Client) SendOTP(ctx, req SendOTPRequest) (*SendOTPResponse, error)` | Request metered OTP delivery (SMS/WA/email) |
| `Client.VerifyOTP` | `(c *Client) VerifyOTP(ctx, identifier, code string) (*AuthResult, error)` | Complete OTP challenge and return tokens |
| `Client.CompletePhone` | `(c *Client) CompletePhone(ctx, req CompletePhoneRequest) (*AuthResult, error)` | Complete `phone_required` challenge |
| `Client.Settings` | `(c *Client) Settings(ctx) (*ProjectSettings, error)` | Fetch cached project login settings |
| `Client.LoginURL` | `(c *Client) LoginURL(ctx, redirectURI string) (string, error)` | Get hosted OIDC login page URL |
| `Client.CompleteLogin` | `(c *Client) CompleteLogin(ctx, code, redirectURI string) (*AuthResult, error)` | Exchange hosted flow auth code for tokens |
| `Client.Me` | `(c *Client) Me(ctx, accessToken string) (*Claims, error)` | Fetch user profile/claims from `/api/v1/auth/me` |
| `Client.ValidateToken` | `(c *Client) ValidateToken(ctx, token string) (*Claims, error)` | Validate token against engine or via JWKS |
| `Client.RefreshToken` | `(c *Client) RefreshToken(ctx, refreshToken string) (string, error)` | Exchange refresh token for fresh access token |
| `Client.Logout` | `(c *Client) Logout(ctx, accessToken string) error` | Revoke session for access token |
| `Client.Forgot` | `(c *Client) Forgot(ctx, req ForgotRequest) (*ForgotResponse, error)` | Trigger password reset flow (OTP or magic link) |
| `Client.Reset` | `(c *Client) Reset(ctx, req ResetRequest) error` | Complete password reset with code/token |
| `Client.ChangePassword` | `(c *Client) ChangePassword(ctx, accessToken string, req ChangePasswordRequest) error` | Update password for authenticated user |
| `Client.ChangeIdentifier`| `(c *Client) ChangeIdentifier(ctx, accessToken string, req ChangeIdentifierRequest) error` | Update verified email or phone |
| `Client.UnlinkGoogle` | `(c *Client) UnlinkGoogle(ctx, accessToken string, req UnlinkGoogleRequest) error` | Detach Google SSO identity |
| `Client.LinkGoogle` | `(c *Client) LinkGoogle(ctx, accessToken, redirectURI string) (string, error)` | Generate Google SSO linking URL |
| `Client.CompleteMembership` | `(c *Client) CompleteMembership(ctx, req CompleteMembershipRequest) (*AuthResult, error)` | Complete `fields_required` challenge |
| `Client.ConfirmLink` | `(c *Client) ConfirmLink(ctx, req ConfirmLinkRequest) (*AuthResult, error)` | Confirm linking Google to existing identity |

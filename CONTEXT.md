# CONTEXT — sureauth-go

## What it is
Official Go client SDK for the sureAuth hosted authentication engine (`github.com/medatechnology/sureauth-go`). Sits in client Go applications to eliminate auth boilerplate.

Client applications use `sureauth-go` to authenticate end users, validate tokens, handle OTP challenges, and drive hosted OIDC logins without hardcoding credentials or hand-rolling JWT verification.

```
Client App (Go) ──sureauth-go──▶ SureAuth Engine (/api/v1/auth/*, /oauth/*)
      │
      └── Local DB (user_profiles: app-specific profile linked to sureauth user_id)
```

## Stack
| Layer | Tech |
|---|---|
| Language | Go 1.23+ |
| Dependencies | Standard library only (`net/http`, `crypto/rsa`, `encoding/json`) |
| Contract | sureAuth engine `/api/v1/auth/*`, `/oauth/*` |

## Architecture — layers
```
client.go       Client struct, HTTP envelope unwrapping, core Auth/Register/Login, OTP, OIDC code exchange
account.go      Account management: Forgot, Reset, ChangePassword, ChangeIdentifier, Link/Unlink Google, challenges
token.go        RS256 JWT parsing, JWKS fetching, local token validation, TokenManager
```

## Conventions
- **Stdlib-only**: Zero third-party dependencies.
- **Zero-config via env**: Reads `SUREAUTH_SERVER_URL` and `SUREAUTH_API_KEY` by default.
- **Challenge result pattern**: Multi-step auth (OTP, phone required) returns `Challenges` in `AuthResult` rather than throwing errors.
- **Typed errors**: API errors map to `*APIError` with Code, Message, Status.

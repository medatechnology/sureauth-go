# INTERNALS — sureauth-go
> Design CHOICE and WHY only. Not file:line — Graft answers "where" live
> and never goes stale; this file only holds what Graft can't infer.

| Concern | Design choice | Why | Rough area (optional) |
|---|---|---|---|
| HTTP envelope handling | Unpack `{success, data, error}` into typed Go structs | Engine wraps all responses in standard envelope; client unwraps transparently | `client.go` (`do`, `doAuthed`) |
| Challenge handling | Return challenges on `AuthResult` instead of returning errors | Engine challenge is not an exceptional failure; client app code handles next step cleanly | `client.go` |
| Token validation | Try engine `/api/v1/auth/validate` or decode RS256 with cached JWKS | Supports offline validation when public key is available | `token.go` |
| Zero-config | `New()` reads `SUREAUTH_SERVER_URL` and `SUREAUTH_API_KEY` | Common pattern for containerized Go apps | `client.go` |

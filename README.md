# sureauth-go

> **Official Go client SDK for the SureAuth authentication engine (`/api/v1/*` + `/oauth/*`).**
> Stdlib-only. Zero external dependencies. Blazingly fast.

---

## 1. Overview & Vision

`sureauth-go` allows Go backends and microservices to integrate with SureAuth in one line.
- Eliminates hand-rolling password hashing, PIN verification, OTP sending, JWT verification, and challenge handling.
- **Golden Copy Architecture**: The app keeps its own local profile table (`user_profiles`) keyed by `sureauth_user_id` (`app_user_id`), while SureAuth maintains credentials, MFA, and global identity deduplication.

---

## 2. Installation & Quickstart

```bash
go get github.com/medatechnology/sureauth-go
```

### One-Line Integration
```go
package main

import (
    "context"
    "fmt"
    "github.com/medatechnology/sureauth-go"
)

func main() {
    ctx := context.Background()
    // Reads SUREAUTH_SERVER_URL + SUREAUTH_API_KEY from env
    client, err := sureauth.New()
    if err != nil {
        panic(err)
    }

    // Register with project-specific settings and optional metadata
    res, err := client.Register(ctx, sureauth.AuthRequest{
        Email:    "user@example.com",
        Password: "SuperSecretPassword123!",
        Metadata: `{"tier":"pro","country":"ID"}`,
    })
    if err != nil {
        panic(err)
    }

    if len(res.Challenges) > 0 {
        fmt.Printf("Next challenge: %s\n", res.Challenges[0].Type)
        return
    }

    fmt.Printf("Authenticated! App User ID: %s, Access Token: %s\n", res.User.ID, res.AccessToken)
}
```

---

## 3. Core Features

- **Non-throwing Challenges**: Multi-step verification (OTP, phone required, fields required, overlap prompt) returns structured challenges rather than errors.
- **Option C Overlap Merge**:
  ```go
  res, err := client.ConfirmMerge(ctx, sureauth.ConfirmMergeRequest{
      Identifier: "user@example.com",
      OTPCode:    "123456",
  })
  ```
- **Custom Metadata**: Update profile metadata directly:
  ```go
  err := client.UpdateMetadata(ctx, accessToken, `{"plan":"enterprise"}`)
  ```
- **OIDC Validation**: Validate RS256 JWT tokens locally via cached JWKS or engine endpoint.

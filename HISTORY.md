# HISTORY — sureauth-go

## Decisions
| # | Decision | Rationale |
|---|---|---|
| 1 | Stdlib-only implementation | Downstream applications do not inherit dependency conflicts or bloat |
| 2 | Challenges flow through AuthResult | Multi-step auth (OTP, phone required) is a normal state, not an error exception |
| 3 | Env-first zero config | Reading `SUREAUTH_SERVER_URL` and `SUREAUTH_API_KEY` enables zero-line config in microservices |
| 4 | RS256 local token validation via JWKS | Avoids network roundtrip to engine for every authenticated request |
| 5 | Migrated legacy markdown into 6-file doc set | AGENTS.md, DESCRIPTION.md, QUICKSTART.md, README.md moved to `.backup/` |

## Features
| Status | Feature | Notes |
|---|---|---|
| shipped | Core register and login | Settings-driven credentials and identifier |
| shipped | OTP challenge completion | Phone / email OTP handling |
| shipped | Hosted OAuth2 / OIDC code exchange | CompleteLogin helper |
| shipped | Account management | Password reset, change identifier, link Google |
| shipped | JWKS and local JWT verification | RS256 claims validation |

## Superseded / removed
- Older MedaAuth library-mode SDKs superseded by hosted engine client.

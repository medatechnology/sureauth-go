# OPS — sureauth-go

## Deployment
Pure Go client library. Imported by consuming applications:
```bash
go get github.com/medatechnology/sureauth-go
```
Local development uses `replace github.com/medatechnology/sureauth-go => ../sureauth-go` in consumer `go.mod`.

## Releasing
- Release triggered by pushing semver tag `vMAJOR.MINOR.BUILD` (e.g. `v1.0.0`).
- No compilation/binary release required.
- Follows `../RELEASE-POLICY.md`.

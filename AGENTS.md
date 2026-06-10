# MITM Proxy Contributor Notes

## Boundaries
- Keep proxy request handling, admin HTTP handlers, persistence, and the embedded React UI separated. Prefer adding small feature-specific files over growing `internal/admin/server.go`, `internal/store/store.go`, or `internal/admin/ui/src/main.jsx`.
- Treat `internal/admin/ui/dist` as a tracked embedded artifact. Any change under `internal/admin/ui/src` must be followed by `npm run build` in `internal/admin/ui` and a clean `git diff --exit-code -- internal/admin/ui/dist`.
- Preserve browser-only query-token support for safe GET/HEAD/OPTIONS links such as streams and downloads. Mutating admin APIs should use `Authorization: Bearer`.

## Verification
- Run `go test ./...` and `go vet ./...` after backend changes.
- Run `npm ci`, `npm run build`, and `npm audit --audit-level=high` from `internal/admin/ui` after UI or dependency changes.
- Use focused tests before broad refactors; characterization tests should land before extracting large handler, store, or UI modules.

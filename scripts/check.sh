#!/usr/bin/env sh
set -euo pipefail
cd "$(dirname "$0")/.."
go test ./...
go vet ./...
if command -v gosec >/dev/null 2>&1; then
  gosec -quiet ./...
else
  echo "gosec not installed; skip (go install github.com/securego/gosec/v2/cmd/gosec@latest)"
fi

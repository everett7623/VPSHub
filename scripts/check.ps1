# Local acceptance helpers: vet, tests, govulncheck, optional gosec, frontend build.
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$GoRoot = Join-Path $env:USERPROFILE "sdk\go1.26.10"
if (-not (Test-Path (Join-Path $GoRoot "bin\go.exe"))) {
  $GoRoot = Join-Path $env:USERPROFILE "sdk\go1.26.9"
}
$GoBin = Join-Path $GoRoot "bin"
if (Test-Path (Join-Path $GoBin "go.exe")) {
  $env:Path = "$GoBin;$env:USERPROFILE\go\bin;" + $env:Path
  $env:GOROOT = $GoRoot
}

Write-Host "== go version =="
go version

Write-Host "== go vet =="
go vet ./...

Write-Host "== go test =="
go test ./...

Write-Host "== govulncheck =="
if (Get-Command govulncheck -ErrorAction SilentlyContinue) {
  govulncheck ./...
} else {
  Write-Host "govulncheck not found; install: go install golang.org/x/vuln/cmd/govulncheck@latest"
}

Write-Host "== gosec (informational) =="
if (Get-Command gosec -ErrorAction SilentlyContinue) {
  gosec -quiet ./...
} else {
  Write-Host "gosec not found; install: go install github.com/securego/gosec/v2/cmd/gosec@latest"
}

Write-Host "== npm build =="
Set-Location (Join-Path $Root "web")
npm run build
Set-Location $Root
Write-Host "OK"

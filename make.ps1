#!powershell
[CmdletBinding()]
Param(
    [Parameter(ParameterSetName='Test')]
    [switch]$Test,

    [Parameter(ParameterSetName='Test')]
    [switch]$VerboseOutput,

    [Parameter(ParameterSetName='Test')]
    [string]$CoverProfile = "cover.out",

    [Parameter(ParameterSetName='Lint')]
    [switch]$Lint,

    [Parameter(ParameterSetName='Build')]
    [switch]$Build,

    [Parameter(ParameterSetName='Build')]
    [string]$OutFile = "damon.exe"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
trap {
    Write-Output "ERROR: $_"
    Write-Output (($_.ScriptStackTrace -split '\r?\n') -replace '^(.*)$','ERROR: $1')
    Exit 1
}

$GOLANG_LINT_VERSION="1.33.0"

## Setup
$env:GOOS="windows"
$env:GOARCH="amd64"
$env:GOFLAGS="-mod=vendor"

## Lint Code
if ($Lint) {
    ## Install Linter
    if (-not (Test-Path -Path .\golangci-lint.exe)) {
        Invoke-WebRequest -OutFile $env:TEMP\golangci-lint.zip -Uri "https://github.com/golangci/golangci-lint/releases/download/v${GOLANG_LINT_VERSION}/golangci-lint-${GOLANG_LINT_VERSION}-windows-amd64.zip"
        Expand-Archive $env:TEMP\golangci-lint.zip $env:TEMP
        Move-Item -Path $env:TEMP\golangci-lint-${GOLANG_LINT_VERSION}-windows-amd64\*.exe -Destination .
    }
    ## Run Linter
    .\golangci-lint.exe run --exclude-use-default
    exit $LASTEXITCODE
}

## Run Test + Coverage
if ($Test) {
    Write-Host "=== Test ==="
    $env:TEST_EXE_PATH = "$PWD\test-damon.exe"
    Write-Host "Compiling ${env:TEST_EXE_PATH}"
    go.exe build -o $env:TEST_EXE_PATH -trimpath -ldflags="-s" ./testcmd/
    if ($env:CI -eq "true") {
        $env:TEST_WIN32_USER_NAME="testuser"
        $env:TEST_WIN32_USER_PASSWORD="test123!"
        $user = Get-LocalUser -Name testuser -ErrorAction SilentlyContinue
        if (-not $user) {
            Write-Host "Create user $env:TEST_WIN32_USER_NAME"
            $password = ConvertTo-SecureString -AsPlainText -String $env:TEST_WIN32_USER_PASSWORD -Force
            New-LocalUser -Name $env:TEST_WIN32_USER_NAME -Password $password | Out-Null
            Write-Host "Assign 'Logon as Batch' rights"
            Start-Process -FilePath $env:TEST_EXE_PATH -ArgumentList "batch_login",$env:TEST_WIN32_USER_NAME | Wait-Process
        }
    }
    $v = if ($VerboseOutput) { "-v" } else { "" }
    go.exe test $v -coverprofile $CoverProfile ./...
    exit $LASTEXITCODE
}

## Run Build
if ($Build) {
    $gitRevision = $(git rev-parse HEAD)
    $gitDescribe = $(git describe 2> $null)
    $buildTimestamp = $(Get-Date -UFormat "%Y-%m-%dT%T%Z")

    $ldflags = "-s"
    $ldflags += " -X github.com/jet/damon/version.GitCommit=${gitRevision}"
    $ldflags += " -X github.com/jet/damon/version.GitDescribe=${gitDescribe}"
    $ldflags += " -X github.com/jet/damon/version.BuildTime=${buildTimestamp}"

    go.exe build -o $OutFile -trimpath -ldflags="$ldflags"
    exit $LASTEXITCODE
}

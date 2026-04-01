[CmdletBinding()]
param(
    [ValidateSet("Release", "Debug")]
    [string]$Configuration = "Release",
    [string]$RuntimeIdentifier = "win-x64",
    [ValidateSet("SelfContained", "FrameworkDependent")]
    [string]$DeploymentMode = "SelfContained"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectPath = Join-Path $scriptRoot "NEUNetworkAutoLogin.Wpf\NEUNetworkAutoLogin.Wpf.csproj"
$publishDir = Join-Path $scriptRoot "publish"
$outputExe = Join-Path $scriptRoot "NEUNetworkAutoLogin.exe"

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    throw "dotnet CLI is not installed. Install .NET 8 SDK first."
}

$sdkList = dotnet --list-sdks
if (-not $sdkList) {
    throw "No .NET SDK found. Install .NET 8 SDK, then rerun this script."
}

if (-not (Test-Path -LiteralPath $projectPath)) {
    throw "Project file not found: $projectPath"
}

if (Test-Path -LiteralPath $publishDir) {
    Remove-Item -LiteralPath $publishDir -Recurse -Force
}

$selfContained = if ($DeploymentMode -eq "SelfContained") { "true" } else { "false" }

$publishArgs = @(
    "publish", $projectPath,
    "-c", $Configuration,
    "-r", $RuntimeIdentifier,
    "--self-contained", $selfContained,
    "-o", $publishDir,
    "/p:PublishSingleFile=true",
    "/p:DebugType=None",
    "/p:DebugSymbols=false"
)

if ($DeploymentMode -eq "SelfContained") {
    $publishArgs += "/p:IncludeNativeLibrariesForSelfExtract=true"
    $publishArgs += "/p:EnableCompressionInSingleFile=true"
}

dotnet @publishArgs

$publishedExe = Join-Path $publishDir "NEUNetworkAutoLogin.exe"
if (-not (Test-Path -LiteralPath $publishedExe)) {
    throw "Publish failed. Expected exe not found: $publishedExe"
}

Copy-Item -LiteralPath $publishedExe -Destination $outputExe -Force

Write-Output "Built single-file EXE ($DeploymentMode):"
Write-Output $outputExe
Write-Output ""
Write-Output "Full publish folder:"
Write-Output $publishDir

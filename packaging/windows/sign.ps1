# Code-signs Windows programs with Azure Trusted Signing (used by the GitHub build).
#
#   pwsh packaging/windows/sign.ps1 file1.exe [file2.exe ...]
#
# Needs these environment variables (repository secrets in the build):
#   AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET   an app registration with the
#       "Trusted Signing Certificate Profile Signer" role on the signing account
#   TRUSTED_SIGNING_ENDPOINT   e.g. https://eus.codesigning.azure.net
#   TRUSTED_SIGNING_ACCOUNT    the Trusted Signing account name
#   TRUSTED_SIGNING_PROFILE    the certificate profile name
param([Parameter(Mandatory, ValueFromRemainingArguments)][string[]]$Files)
$ErrorActionPreference = 'Stop'

foreach ($v in 'AZURE_TENANT_ID', 'AZURE_CLIENT_ID', 'AZURE_CLIENT_SECRET', 'TRUSTED_SIGNING_ENDPOINT', 'TRUSTED_SIGNING_ACCOUNT', 'TRUSTED_SIGNING_PROFILE') {
    if (-not [Environment]::GetEnvironmentVariable($v)) { throw "$v is not set" }
}

$work = Join-Path ([IO.Path]::GetTempPath()) 'rd-signing'
New-Item -ItemType Directory -Force $work | Out-Null

# The signing client: a plug-in for signtool that signs in Azure.
$dlib = Get-ChildItem $work -Recurse -Filter Azure.CodeSigning.Dlib.dll -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match '\\x64\\' } | Select-Object -First 1
if (-not $dlib) {
    nuget install Microsoft.Trusted.Signing.Client -OutputDirectory $work -NonInteractive | Out-Host
    $dlib = Get-ChildItem $work -Recurse -Filter Azure.CodeSigning.Dlib.dll | Where-Object { $_.FullName -match '\\x64\\' } | Select-Object -First 1
}
if (-not $dlib) { throw "the Trusted Signing client wasn't found after installing it" }

$signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" | Sort-Object FullName | Select-Object -Last 1
if (-not $signtool) { throw "signtool.exe not found (Windows SDK)" }

$metadata = Join-Path $work 'metadata.json'
@{
    Endpoint               = $env:TRUSTED_SIGNING_ENDPOINT
    CodeSigningAccountName = $env:TRUSTED_SIGNING_ACCOUNT
    CertificateProfileName = $env:TRUSTED_SIGNING_PROFILE
} | ConvertTo-Json | Set-Content -Encoding utf8 $metadata

& $signtool.FullName sign /v /fd SHA256 /tr http://timestamp.acs.microsoft.com /td SHA256 /dlib $dlib.FullName /dmdf $metadata @Files
if ($LASTEXITCODE -ne 0) { throw "signing failed" }
& $signtool.FullName verify /pa /v @Files | Out-Host
if ($LASTEXITCODE -ne 0) { throw "a signature didn't verify" }

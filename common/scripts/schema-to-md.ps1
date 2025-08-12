# schema-to-md.ps1
# Usage: .\schema-to-md.ps1 <schema.json>

param(
    [string]$SchemaFile
)

Write-Output "|Field|Column|"
Write-Output "|-|-|"

# Use jq for consistent output with bash version
$jq = "jq.exe" # Assumes jq.exe is in PATH or same directory
# If jq is not in PATH, fallback to jq if installed globally
if (-not (Get-Command $jq -ErrorAction SilentlyContinue)) { $jq = "jq" }

# Run jq and process output in PowerShell
$jqlines = & $jq -r -f $PSScriptRoot/schema_paths.jq $SchemaFile
foreach ($line in $jqlines -split ",") {
    # Replace .[]. with []. using PowerShell
    $fixed = $line -replace '\.\[\]\.', '[].'
    Write-Output $fixed
}

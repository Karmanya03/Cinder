[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)][ValidatePattern('^v\d+\.\d+\.\d+$')][string]$Version,
    [switch]$SkipPush
)
$ErrorActionPreference = 'Stop'

if (-not (Test-Path .git)) { throw 'Run this script from the repository root.' }
if ((git status --porcelain) -ne '') { throw 'Release requires a clean worktree.' }
git fetch --tags origin
if (git tag --list $Version) { throw "Tag $Version already exists." }
if ($PSCmdlet.ShouldProcess($Version, 'create annotated release tag')) {
    git tag -a $Version -m "Cinder $Version"
    if (-not $SkipPush) {
        git push origin $Version
        Write-Output "Pushed $Version; GitHub Actions will build and attest the release."
    } else {
        Write-Output "Created $Version locally. Push it when ready."
    }
}

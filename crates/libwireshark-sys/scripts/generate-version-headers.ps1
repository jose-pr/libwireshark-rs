param(
    [string] $RepositoryPath = (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent | Split-Path -Parent) 'wireshark-src'),
    [string] $OutputDirectory = (Join-Path (Split-Path $PSScriptRoot -Parent) 'headers'),
    [string] $RemoteUrl = 'https://github.com/wireshark/wireshark.git',
    [string] $Architecture,
    [string] $TargetOS
)

$ErrorActionPreference = 'Stop'
$repository = [IO.Path]::GetFullPath($RepositoryPath)
$outputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
$workspace = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..'))
if (-not $Architecture) {
    $Architecture = switch ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()) {
        'Arm64' { 'aarch64' }
        'X64' { 'x86_64' }
        'X86' { 'x86' }
        'Arm' { 'arm' }
        default { throw "Unsupported host architecture: $([Runtime.InteropServices.RuntimeInformation]::OSArchitecture)" }
    }
}
if (-not $TargetOS) {
    $TargetOS = switch ([Runtime.InteropServices.RuntimeInformation]::OSDescription) {
        { $_ -match 'Windows' } { 'windows'; break }
        { $_ -match 'Darwin|macOS' } { 'macos'; break }
        default { 'linux' }
    }
}
if ($TargetOS -notin @('windows', 'linux', 'macos')) {
    throw "Unsupported Rust target operating system: $TargetOS"
}
if ($Architecture -notmatch '^[a-zA-Z0-9_]+$') {
    throw "Invalid Rust target architecture: $Architecture"
}

if (-not (Test-Path -LiteralPath $repository)) {
    & git clone --filter=blob:none --no-checkout $RemoteUrl $repository
    if ($LASTEXITCODE -ne 0) {
        throw "Could not clone the Wireshark source repository (exit code $LASTEXITCODE)."
    }
}
if (-not (Test-Path -LiteralPath (Join-Path $repository '.git'))) {
    throw "The repository path is not a Git checkout: $repository"
}
$actualRemote = (& git -C $repository remote get-url origin | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $actualRemote -ne $RemoteUrl) {
    throw "The origin at $repository must be $RemoteUrl (found $actualRemote)."
}

& git -C $repository fetch --filter=blob:none --tags origin
if ($LASTEXITCODE -ne 0) {
    throw "Could not fetch Wireshark release tags (exit code $LASTEXITCODE)."
}

$releaseLines = @(
    & git -C $repository tag --list 'v*' |
        ForEach-Object {
            if ($_ -match '^v(?<major>\d+)\.(?<minor>\d+)\.0$' -and
                ([int]$Matches.major -ge 3) -and ([int]$Matches.minor % 2) -eq 0) {
                [pscustomobject]@{ Tag = $_; Major = [int]$Matches.major; Minor = [int]$Matches.minor }
            }
        } |
        Sort-Object Major, Minor
)
if ($releaseLines.Count -eq 0) {
    throw 'No stable Wireshark release lines from major version 3 onward (vX.Y.0 with an even minor) were found.'
}

New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null
$worktreeBase = Join-Path ([IO.Path]::GetTempPath()) "libwireshark-rs-header-source-$([Guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $worktreeBase | Out-Null
Push-Location $workspace
try {
    foreach ($release in $releaseLines) {
        $worktree = Join-Path $worktreeBase $release.Tag
        Write-Host "Generating Wireshark $($release.Major).$($release.Minor) headers from $($release.Tag)"
        & git -C $repository worktree add --quiet --detach $worktree $release.Tag
        if ($LASTEXITCODE -ne 0) {
            throw "Could not create a source worktree for Wireshark release $($release.Tag)."
        }
        try {
            $output = Join-Path $outputDirectory "$($release.Major)-$($release.Minor)-$TargetOS-$Architecture.h"
            & cargo run --quiet -p cargo-wireshark -- wireshark headers --source-dir $worktree --output $output --arch $Architecture --target-os $TargetOS
            if ($LASTEXITCODE -ne 0) {
                throw "Header generation failed for Wireshark $($release.Major).$($release.Minor) at $($release.Tag)."
            }
        }
        finally {
            & git -C $repository worktree remove --force $worktree
            if ($LASTEXITCODE -ne 0) {
                throw "Could not remove the temporary source worktree for $($release.Tag)."
            }
        }
    }
}
finally {
    Pop-Location
    if ((Test-Path -LiteralPath $worktreeBase) -and
        [IO.Directory]::GetFileSystemEntries($worktreeBase).Length -eq 0) {
        [IO.Directory]::Delete($worktreeBase)
    }
}

Write-Output "Generated $($releaseLines.Count) stable Wireshark release-line headers for $TargetOS-$Architecture in $outputDirectory."

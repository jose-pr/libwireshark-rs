param(
    [Parameter(Mandatory = $true)]
    [string] $DllPath,
    [string] $OutputPath,
    [ValidateSet('auto', 'x86', 'x64', 'arm64')]
    [string] $Architecture = 'auto'
)

$ErrorActionPreference = 'Stop'
$resolvedDll = (Resolve-Path -LiteralPath $DllPath).Path
$readObj = Get-Command llvm-readobj -ErrorAction Stop
$dllTool = Get-Command llvm-dlltool -ErrorAction Stop
$inspection = (& $readObj.Source --coff-exports $resolvedDll 2>&1 | Out-String)
if ($LASTEXITCODE -ne 0) {
    throw "llvm-readobj could not inspect the DLL (exit code $LASTEXITCODE)"
}

$machine = switch -Regex ($inspection) {
    'Arch: aarch64' { 'arm64'; break }
    'Arch: x86_64' { 'x64'; break }
    'Arch: i386' { 'x86'; break }
}
if (-not $machine) {
    throw 'The DLL architecture is not a supported x86, x64, or ARM64 target.'
}
if ($Architecture -ne 'auto' -and $Architecture -ne $machine) {
    throw "Requested architecture $Architecture does not match the DLL architecture $machine."
}

$exportMatches = [regex]::Matches(
    $inspection,
    '(?ms)^Export \{\s*Ordinal: (?<ordinal>\d+)\s*Name: (?<name>[^\r\n]+)'
)
if ($exportMatches.Count -eq 0) {
    throw 'No named exports were found in the DLL.'
}

if (-not $OutputPath) {
    $libraryName = [IO.Path]::GetFileNameWithoutExtension($resolvedDll)
    if ($libraryName.StartsWith('lib', [StringComparison]::OrdinalIgnoreCase)) {
        $libraryName = $libraryName.Substring(3)
    }
    $OutputPath = Join-Path (Get-Location) ($libraryName + '.lib')
}
$OutputPath = [IO.Path]::GetFullPath($OutputPath)
$outputDirectory = [IO.Path]::GetDirectoryName($OutputPath)
if (-not (Test-Path -LiteralPath $outputDirectory -PathType Container)) {
    throw 'The import library output directory does not exist.'
}

$definitionPath = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString() + '.def')
try {
    $definition = [Collections.Generic.List[string]]::new()
    $definition.Add('LIBRARY ' + [IO.Path]::GetFileName($resolvedDll))
    $definition.Add('EXPORTS')
    foreach ($entry in $exportMatches) {
        $name = $entry.Groups['name'].Value.Trim()
        $ordinal = $entry.Groups['ordinal'].Value
        if ($name -notmatch '[\s,;]') {
            $definition.Add("$name @$ordinal")
        }
    }
    [IO.File]::WriteAllLines($definitionPath, $definition, [Text.UTF8Encoding]::new($false))
    & $dllTool.Source -m $machine -D ([IO.Path]::GetFileName($resolvedDll)) -d $definitionPath -l $OutputPath
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $OutputPath -PathType Leaf)) {
        throw "llvm-dlltool failed to create the import library (exit code $LASTEXITCODE)"
    }
    Write-Output $OutputPath
}
finally {
    Remove-Item -LiteralPath $definitionPath -Force -ErrorAction SilentlyContinue
}

param([Parameter(Mandatory)][string]$Version)
$ErrorActionPreference = 'Stop'
if ($Version -notmatch '^[0-9A-Za-z.-]+$') { throw 'Unsafe package version' }
$files = @('huawei-pc-manager-bootstrap.exe', 'huawei_pc_manager_bootstrap_core.dll')
foreach ($file in $files) {
    if (!(Test-Path "dist/$file" -PathType Leaf)) { throw "Missing bundle file: $file" }
    if ((Get-Item "dist/$file").Length -eq 0) { throw "Empty bundle file: $file" }
}
New-Item -ItemType Directory -Force release | Out-Null
$name = "huawei-pc-manager-bootstrap-$Version.zip"
$zip = Join-Path 'release' $name
Compress-Archive -LiteralPath ($files | ForEach-Object { "dist/$_" }) -DestinationPath $zip -Force
# Inspect the actual archive, not just its inputs.
$archive = [IO.Compression.ZipFile]::OpenRead((Resolve-Path $zip))
try {
    $entries = @($archive.Entries | ForEach-Object { $_.FullName } | Sort-Object)
    if (Compare-Object ($files | Sort-Object) $entries) { throw 'Unexpected ZIP contents' }
} finally { $archive.Dispose() }
$hash = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText((Join-Path (Resolve-Path 'release') 'SHA256SUMS.txt'), "$hash  $name`n", [Text.UTF8Encoding]::new($false))

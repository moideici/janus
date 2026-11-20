# Builds clients/java/out/janus.jar with the JDK only (javac + jar). Run from anywhere.
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
if (Test-Path out/classes) { Remove-Item -Recurse -Force out/classes }
New-Item -ItemType Directory -Force out/classes | Out-Null
$sources = Get-ChildItem src/org/janus/*.java | ForEach-Object { $_.FullName }
& javac --release 21 -encoding UTF-8 -Xlint:all -d out/classes $sources
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& jar --create --file out/janus.jar --main-class org.janus.Main -C out/classes .
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Output "built $PSScriptRoot\out\janus.jar"

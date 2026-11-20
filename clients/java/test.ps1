# Builds, then runs the self-test (vectors, round trips, interoperability with janus-rs).
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
& ./build.ps1
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& java -cp out/janus.jar org.janus.Tests ../..
exit $LASTEXITCODE

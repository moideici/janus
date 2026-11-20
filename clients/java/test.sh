#!/bin/sh
# Builds, then runs the self-test (vectors, round trips, interoperability with janus-rs).
set -e
cd "$(dirname "$0")"
./build.sh
exec java -cp out/janus.jar org.janus.Tests ../..

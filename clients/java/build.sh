#!/bin/sh
# Builds clients/java/out/janus.jar with the JDK only (javac + jar). Run from anywhere.
set -e
cd "$(dirname "$0")"
rm -rf out/classes
mkdir -p out/classes
javac --release 21 -encoding UTF-8 -Xlint:all -d out/classes src/org/janus/*.java
jar --create --file out/janus.jar --main-class org.janus.Main -C out/classes .
echo "built $(pwd)/out/janus.jar"

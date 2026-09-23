#!/usr/bin/env sh
# builds out/ and a runnable qunprotect-lite.jar
set -e
SEP=":"; case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) SEP=";";; esac
CP=$(printf "%s$SEP" lib/*.jar)
rm -rf out build; mkdir -p out build
javac -cp "$CP" -d out $(find src -name '*.java')
cd build
for j in ../lib/*.jar; do unzip -o -q "$j" -x 'META-INF/*'; done
cp -r ../out/* .
printf 'Manifest-Version: 1.0\nMain-Class: qp.deob.Deobfuscator\n' > mf.mf
jar cfm ../qunprotect-lite.jar mf.mf .
cd ..; rm -rf build
echo "built qunprotect-lite.jar"

@echo off
setlocal
set CP=lib\asm-9.9.jar;lib\asm-analysis-9.9.jar;lib\asm-commons-9.9.jar;lib\asm-tree-9.9.jar;lib\asm-util-9.9.jar
if exist out rmdir /s /q out
mkdir out
dir /s /b src\*.java > sources.txt
javac -cp "%CP%" -d out @sources.txt
del sources.txt
jar cfe qunprotect-lite.jar qp.deob.Deobfuscator -C out .
echo built qunprotect-lite.jar (needs lib\*.jar on classpath to run)

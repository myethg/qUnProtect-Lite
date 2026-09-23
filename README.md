# qUnProtect-Lite

deobfs jars that got run through qProtect Lite. feed it a protected jar, get a clean runnable jar back. its fully static, it never runs the input.

what it undoes:
- string encryption, both the xor and aes ones, finds the keys itself per class
- invokedynamic call hiding, puts it back to normal calls
- number obfuscation, folds the math back
- flow junk (fake if checks, flipped jumps, useless checkcasts, junk) + dead code
- the trick where a class is stored as `App.class/` so decompilers cant see it
- reads java 25 (v69) classfiles too

line numbers and local var names that got stripped dont come back, thats just gone.

## need
jdk 17+ (25 works), asm 9.x jars, already in lib/.

## build (git bash / windows)
```
CP="lib/asm-9.9.jar;lib/asm-analysis-9.9.jar;lib/asm-commons-9.9.jar;lib/asm-tree-9.9.jar;lib/asm-util-9.9.jar"
javac -cp "$CP" -d out $(find src -name '*.java')
```
on linux/mac the classpath separator is `:` not `;`

## run
```
java -cp "out;$CP" qp.deob.Deobfuscator <in.jar|dir> <out.jar|dir> [options]
```
in and out can be a jar or a folder of .class files.

## options
- `--passes` list the passes and quit
- `--only x,y` only run those passes
- `--stop-after x`
- `--stages dir` dump every class after each pass so u can watch it step by step
- `--print file.class` dump a class, works on v69 that javap breaks on
- `-v` verbose
- `--no-color`
- `-h`

passes in order: polymorph, numberfold, strings, indy, opaque, reversejump, checkcast, dce, synthetic, infostrip.

## output
prints each pass as it runs like:
```
[strings] App: decrypted 27 strings
[indy] App: resolved 18 calls
App: FULLY DEOBFUSCATED
```
then a small summary at the end. its colored.
do whateveer with the code just credit thanks when I obtain qprotect premium samples I will make a deobfuscator for that too.


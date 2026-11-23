#!/bin/sh
# Compile once against the released 0.7 API; never compile against the candidate.
set -eu
if [ "$#" -ne 3 ]; then
    echo "Usage: sh verify.sh zero-allocation-hashing-0.7.jar candidate.jar no-alias-control.jar" >&2
    exit 2
fi
java=java
javac=javac
if [ -n "${JAVA_HOME:-}" ]; then
    java="$JAVA_HOME/bin/java"
    javac="$JAVA_HOME/bin/javac"
fi
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
"$javac" -source 7 -target 7 -cp "$1" -d "$work" "$(dirname "$0")/LegacyAliasConsumer.java"
compiled=$(cksum "$work/LegacyAliasConsumer.class")
for mode in unseeded seeded; do
    "$java" -cp "$work:$2" LegacyAliasConsumer "$mode"
    if "$java" -cp "$work:$3" LegacyAliasConsumer "$mode" >"$work/control-$mode.log" 2>&1; then
        echo "Control unexpectedly linked the $mode legacy signature" >&2
        exit 1
    fi
    if ! grep 'NoSuchMethodError.*xx_r39' "$work/control-$mode.log" >/dev/null; then
        cat "$work/control-$mode.log" >&2
        echo "Control failed for a reason other than the missing legacy signature" >&2
        exit 1
    fi
    echo "PASS $mode control: missing legacy descriptor rejected"
done
test "$compiled" = "$(cksum "$work/LegacyAliasConsumer.class")"
echo "PASS consumer bytecode unchanged across candidate and control runs"

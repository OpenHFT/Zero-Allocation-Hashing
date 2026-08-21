# Issue #67: absolute-long-offset VarHandle adapter experiment

Status: rejected as a production implementation. This directory records the
experiment from pull request #121; it is research evidence, not code proposed
for `develop`.

## Scoped conclusion

On the tested JDKs and payload sizes, adapting the existing absolute-`long`-
offset `Access` API to byte-array view VarHandles makes whole XXH3 hashes slower
than the existing Unsafe implementation. This adapter is therefore unsuitable
as a drop-in replacement.

This result does not establish that VarHandle is inherently slower than Unsafe.
In particular, it does not evaluate a specialised relative-`int`-offset path,
XxHash, streaming or file input, heap or direct `ByteBuffer`, raw memory, or an
implementation designed independently of the existing Unsafe-shaped API.

The adapter is not a fallback for denied Unsafe memory access. It obtains
`UnsafeAccess.BYTE_BASE`, which initialises `UnsafeAccess` and invokes Unsafe
memory-access methods. XXH3 also continues to read its secret through
`UnsafeAccess`.

## Experiment identity

- Repository base: `develop` at
  `44f5e8cae1b862a731fbc7d469c8d87e159907dc`.
- Original pull-request head:
  `15971be0c616447c0595a664ef76ffc38b8f2f9b`.
- `prototype.patch` contains the experimental adapter, differential test and
  benchmark. Its Maven profile was made explicit and reproducible for this
  archive; it is not activated by an ordinary build.
- JMH version: 1.37.

## Equivalence evidence

`VarHandleAccessTest` performs 2,730 comparisons per execution:

- ten 64-bit hash-function configurations over lengths 0 through 264; and
- the same ten configurations at eight unaligned prefixes.

Every comparison matched the existing Unsafe path. This is useful differential
evidence for the tested `byte[]` adapter. It is not an external specification,
an Unsafe-denial test, or coverage of every public input form. The retained
`raw/equivalence-test.log` records both Surefire executions and the complete
14,903-test build result.

## Performance evidence

The benchmark hashes the same repeatedly accessed `byte[]` with unseeded XXH3.
The methods receive the same absolute offset, but the VarHandle adapter performs
`(int) (offset - BYTE_BASE)` on each read. That coordinate conversion is part of
the implementation measured.

The original matrix used AverageTime in ns/op, two forks, three 500 ms warm-up
iterations and five 500 ms measurement iterations. It covered lengths 8, 16,
64, 128, 1024 and 4096 at starting alignments 0 and 1.

| Input | VarHandle cost over Unsafe across JDK 11/17/21/25 |
| --- | --- |
| 8 bytes | 6% to 20% |
| 16 bytes | 10% to 18% |
| 64 bytes | 22% to 27% |
| 128 bytes | 11% to 28% |
| 1024 bytes | 35% to 62% |
| 4096 bytes | 13% to 45% |

`results-summary.txt` contains every aggregate score and confidence-interval
half-width. The `raw` directory contains the original JMH JSON and console logs.
An independent JDK 21 rerun on 2026-08-21 reproduced all 12 parameter pairs:
the adapter was 12% to 59% slower. Its output is retained as
`raw/reproduction-jdk21.{json,log}`.

## Environment

- Host: Intel Core Ultra 9 185H, x86-64, 22 online logical CPUs.
- OS: Ubuntu 24.04, Linux `7.0.0-28-generic`.
- JDKs:
  - OpenJDK 11.0.31+11-post-1ubuntu1-24.04.2-Ubuntu;
  - OpenJDK 17.0.19+10-1-24.04.2-Ubuntu;
  - OpenJDK 21.0.11+10-1-24.04.2-Ubuntu;
  - OpenJDK 25.0.3+9-2-24.04.2-Ubuntu.
- JVM arguments: none.
- The host was shared and CPU frequency was not pinned. Treat the direction as
  credible, but do not treat the percentages as a cross-machine performance
  guarantee.

## Reproduction

The exact original shell command was not retained. The following command
reconstructs the settings recorded by JMH and was used for the retained JDK 21
reproduction:

```bash
git switch develop
git apply research/issue-67/prototype.patch

export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
export PATH="$JAVA_HOME/bin:$PATH"

mvn -B -DvarhandlePrototype clean test \
  -Dtest=VarHandleAccessTest \
  dependency:build-classpath \
  -Dmdep.outputFile=target/test-classpath.txt \
  -DincludeScope=test

JMH_CP=$(sed -n '1p' target/test-classpath.txt)
java -cp "target/test-classes:target/classes:$JMH_CP" \
  org.openjdk.jmh.Main \
  'net.openhft.hashing.VarHandleVsUnsafeBenchmark.*' \
  -bm avgt -f 2 -wi 3 -w 500ms -i 5 -r 500ms \
  -rf json -rff results-jdk21.json -o run-jdk21.log
```

## Consequence

Do not merge or ship this adapter. A successor investigation should design the
complete supported-memory-access architecture before selecting an
implementation. It should compare natural coordinate models and specialised
algorithm paths, cover every public input form, work without Unsafe memory
access on its modern path, preserve the Java 8 artefact, and retain complete
correctness and benchmark evidence.

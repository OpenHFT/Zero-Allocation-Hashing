# Zero-allocation Hashing
[![Build Status](https://travis-ci.org/OpenHFT/Zero-Allocation-Hashing.svg?branch=master)](https://travis-ci.org/OpenHFT/Zero-Allocation-Hashing)

This project provides the API ([JavaDocs](http://openhft.github.io/Zero-Allocation-Hashing/apidocs/))
for hashing any sequences of bytes in Java, including all kinds of
primitive arrays, buffers, `CharSequence`s and more. Java 6+. Apache 2.0 licence.

The key design goal, distinguishing this project from, for example, [Guava hashing](
http://docs.guava-libraries.googlecode.com/git-history/release/javadoc/com/google/common/hash/package-summary.html):
this API ease implementing hashing algorithms which **don't do a single allocation
during hash computation for any input**, and without using `ThreadLocal`.

Also, **the API attemps to be agile enough in byte order treatment**, favoring native access,
but allowing the hash function implementation be platform-endianness-agnostic. On the other hand,
it allows to "fool" the existing implementation, even sealed for one byte order, feeding data
in different byte order and obtain consistent results, only moderately compromising performance.

Currently `long`-valued hash function interface is defined, with a plenty of shipped
implementations:
 - **[xxHash](https://github.com/Cyan4973/xxHash), r39** (latest; r40-r42 are maintenance releases
 without algorithm changes).

 - Two algorithms from **[FarmHash](https://github.com/google/farmhash)**: `farmhashna` (introduced
 in FarmHash 1.0) and `farmhashuo` (introduced in FarmHash 1.1)

 - **[CityHash](https://code.google.com/p/cityhash/), version 1.1** (latest; 1.1.1 is a C++
 language-specific maintenance release).

 - **[MurmurHash3](https://code.google.com/p/smhasher/wiki/MurmurHash3)**.

These implementations are thought to be independent from the native byte order. They are thoroughly
tested with JDK 6, 7 and 8, but only on little-endian platform.

#### Performance

Tested on Intel Core i7-4870HQ CPU @ 2.50GHz

Algorithm     | Speed, GB/s | Bootstrap, ns
--------------|-------------|--------------
xxHash        | 9.5         | 6
FarmHash `na` | 9.0         | 6
FarmHash `uo` | 7.2         | 7
CityHash      | 7.0         | 7
MurmurHash    | 5.3         | 12

To sum up,

#### When to use this project
 - You need to hash plain byte sequences, memory blocks or "flat" objects.
 - You like zero-allocation and pretty good performance (at Java scale).
 - You need hashing to be agile in questions related to byte ordering.

#### When *not* to use:
 - You need to hash POJOs whose actual data is scattered in memory between managed objects.
   There is no simple way to hash, for example, instances of such class:

   ```java
    class Person {
        String givenName, surName;
        int salary;
    }
   ```
   using the API provided by this project.
 - You need to hash byte sequences of beforehand unknown length, for the simpliest example,
   `Iterator<Byte>`.
 - You need to transform the byte sequence (e. g. encode or decode it with a specific coding),
   and hash the resulting byte sequence on the way without dumping it to memory.

## Quick start

Gradle:
```groovy
dependencies {
    compile 'net.openhft:zero-allocation-hashing:0.4'
}
```

Or Maven:
```xml
<dependency>
  <groupId>net.openhft</groupId>
  <artifactId>zero-allocation-hashing</artifactId>
  <version>0.4</version>
</dependency>
```

In Java:
```java
long hash = LongHashFunction.xx_r39().hashChars("hello");
```

See **[JavaDocs](http://openhft.github.io/Zero-Allocation-Hashing/apidocs/)** for more information.

## Contributions are most welcome!

See the list of [open issues](https://github.com/OpenHFT/Zero-Allocation-Hashing/issues).

# Zero-allocation Hashing
![travis status](https://travis-ci.org/OpenHFT/zero-allocation-hashing.svg)

This project provides API for hashing any sequences of bytes in Java, including all kinds of
primitive arrays, buffers, `CharSequence`s and more. Java 6+. Apache 2.0 licence.

Key design goal, distinguishing this project from, for example, [Guava hashing API](
http://docs.guava-libraries.googlecode.com/git-history/release/javadoc/com/google/common/hash/package-summary.html):
this API ease implementing hashing algorithms which **don't do a single allocation
during hash computation for any input** (and shipped implementation, indeed, doesn't do one).

Also, **API attemps to be agile enough about byte order treatment**, favoring native access,
but allowing the hash function implementation be platform-endianness-agnostic. On the other hand,
it allows to "fool" existing implementation, even sealed for one byte order, feeding data
in different byte order and and obtain consistent results,
still compromising performance moderately.

Currently only `long`-valued hash function interface is defined, with a single shipped
implementation:
 - **[CityHash](https://code.google.com/p/cityhash/), version 1.1**
   (latest; 1.1.1 is C++ language-specific fixing release). This implementation is thought
   to be independent from native byte order. It is thoroughly, I believe, tested with
   JDK 6, 7 and 8, but only on little-endian platform. On my developer machine, it performs on the
   speed of **5-6 bytes/ns** with **11 ns bootstrap** for sequences of any length.

When to use this project:
 - you need to hash plain byte sequences, memory blocks or "flat" objects
 - you like zero-allocation and pretty good performance (at Java scale)
 - you need hashing to be agile in questions related to byte ordering

When not to use:
 - you need to hash POJOs whose actual data is scattered in memory between managed objects.
   There is no simple way to hash even instances of such class:
```java
class Person {
    String givenName, surName;
    int salary;
}
```
using API provided by this project.
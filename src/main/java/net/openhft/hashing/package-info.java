/*
 * Copyright 2013-2025 chronicle.software; SPDX-License-Identifier: Apache-2.0
 */
/**
 * API for hashing sequential data and zero-allocation, pretty fast implementations
 * of non-cryptographic hash functions.
 *
 * <p>Currently implemented (in alphabetical order):
 * <ul>
 *     <li>{@code long}-valued functions: see {@link net.openhft.hashing.LongHashFunction}
 *     <ul>
 *         <li>
 *         {@linkplain net.openhft.hashing.LongHashFunction#city_1_1() CityHash 1.1 without seeds},
 *         {@linkplain net.openhft.hashing.LongHashFunction#city_1_1(long) with one seed} and
 *         {@linkplain net.openhft.hashing.LongHashFunction#city_1_1(long, long) with two seeds}.
 *         </li>
 *         <li>
 *         {@linkplain net.openhft.hashing.LongHashFunction#farmNa() FarmHash 1.0 (farmhashna)
 *         without seed}, {@linkplain net.openhft.hashing.LongHashFunction#farmNa(long) with one
 *         seed} and {@linkplain net.openhft.hashing.LongHashFunction#farmNa(long, long) with
 *         two seeds}.
 *         </li>
 *         <li>
 *         {@linkplain net.openhft.hashing.LongHashFunction#farmUo() FarmHash 1.1 (farmhashuo)
 *         without seed}, {@linkplain net.openhft.hashing.LongHashFunction#farmUo(long) with one
 *         seed} and {@linkplain net.openhft.hashing.LongHashFunction#farmUo(long, long) with
 *         two seeds}.
 *         </li>
 *         <li>
 *         {@linkplain net.openhft.hashing.LongHashFunction#metro() MetroHash without seed} and
 *         {@linkplain net.openhft.hashing.LongHashFunction#metro(long) with a seed}.
 *         </li>
 *         <li>
 *         {@linkplain net.openhft.hashing.LongHashFunction#murmur_3() 64-bit MurmurHash3 without seed} and
 *         {@linkplain net.openhft.hashing.LongHashFunction#murmur_3(long) with a seed}.
 *         </li>
 *         <li>
 *         {@linkplain net.openhft.hashing.LongHashFunction#wy_3() WyHash v3 without seed} and
 *         {@linkplain net.openhft.hashing.LongHashFunction#wy_3(long) with a seed}.
 *         </li>
 *         <li>
 *         {@linkplain net.openhft.hashing.LongHashFunction#xx() xxHash without seed} and
 *         {@linkplain net.openhft.hashing.LongHashFunction#xx(long) with a seed}.
 *         </li>
 *     </ul>
 *     </li>
 * </ul>
 *
 * <p>API for hashing sequential data to more than 64-bit result, pretty fast implementations of
 * non-cryptographic hash functions.
 *
 * <p>Currently implemented (in alphabetical order):
 * <ul>
 *     <li>{@code long[]}-valued functions: see {@link net.openhft.hashing.LongTupleHashFunction}
 *     <ul>
 *         <li>
 *         {@linkplain net.openhft.hashing.LongTupleHashFunction#murmur_3() 128-bit MurmurHash3 without seed}
 *         and {@linkplain net.openhft.hashing.LongTupleHashFunction#murmur_3(long) with a seed}.
 *         </li>
 *     </ul>
 *     </li>
 * </ul>
 */
package net.openhft.hashing;

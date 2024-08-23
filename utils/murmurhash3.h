/**
 * @file murmurhash3.h
 * @brief Header file for the MurmurHash3 hash function
 * @author Andrea Efficace (andrea.efficace1@gmail.com
 */

//-----------------------------------------------------------------------------
// MurmurHash3 was written by Austin Appleby, and is placed in the public
// domain. The author hereby disclaims copyright to this source code.
// This work is taken from - https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.h
// and adapted to be used in the kReMFiP project
//-----------------------------------------------------------------------------

#ifndef MURMURHASH3_H
#define MURMURHASH3_H

#include <linux/types.h>
#include <linux/mm.h>

uint32_t murmur3_x86_32(const char *key, int len, uint32_t seed);
uint32_t* murmur3_x86_128(const void *key, int len, uint32_t seed);
uint64_t* murmur3_x64_128(const void *key, int len, uint32_t seed);
#endif // MURMURHASH3_H
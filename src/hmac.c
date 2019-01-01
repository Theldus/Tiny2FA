/*
 * MIT License
 *
 * Copyright (c) 2018 Davidson Francis <davidsondfgl@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 *
 *
 * This file previously have made use of the function 'explicit_bzero', provided
 * from the file util.c/util.h in order to avoid GCC optimizations in the
 * function.
 * 
 * Since util.c makes use of a header not present in the original project
 * (config.h), I've intentionally excluded the use of util.h and replaced the
 * function for the original 'bzero', present in the default C library.
 *
 * The previous authors terms are included below:
 */

// HMAC_SHA1 implementation
//
// Copyright 2010 Google Inc.
// Author: Markus Gutschke
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <string.h>
#include <strings.h>

#include "hmac.h"
#include "sha1.h"

void hmac_sha1(const uint8_t *key, int keyLength,
               const uint8_t *data, int dataLength,
               uint8_t *result, int resultLength) {
  SHA1_INFO ctx;
  uint8_t hashed_key[SHA1_DIGEST_LENGTH];
  if (keyLength > 64) {
    // The key can be no bigger than 64 bytes. If it is, we'll hash it down to
    // 20 bytes.
    sha1_init(&ctx);
    sha1_update(&ctx, key, keyLength);
    sha1_final(&ctx, hashed_key);
    key = hashed_key;
    keyLength = SHA1_DIGEST_LENGTH;
  }

  // The key for the inner digest is derived from our key, by padding the key
  // the full length of 64 bytes, and then XOR'ing each byte with 0x36.
  uint8_t tmp_key[64];
  for (int i = 0; i < keyLength; ++i) {
    tmp_key[i] = key[i] ^ 0x36;
  }
  if (keyLength < 64) {
    memset(tmp_key + keyLength, 0x36, 64 - keyLength);
  }

  // Compute inner digest
  sha1_init(&ctx);
  sha1_update(&ctx, tmp_key, 64);
  sha1_update(&ctx, data, dataLength);
  uint8_t sha[SHA1_DIGEST_LENGTH];
  sha1_final(&ctx, sha);

  // The key for the outer digest is derived from our key, by padding the key
  // the full length of 64 bytes, and then XOR'ing each byte with 0x5C.
  for (int i = 0; i < keyLength; ++i) {
    tmp_key[i] = key[i] ^ 0x5C;
  }
  memset(tmp_key + keyLength, 0x5C, 64 - keyLength);

  // Compute outer digest
  sha1_init(&ctx);
  sha1_update(&ctx, tmp_key, 64);
  sha1_update(&ctx, sha, SHA1_DIGEST_LENGTH);
  sha1_final(&ctx, sha);

  // Copy result to output buffer and truncate or pad as necessary
  memset(result, 0, resultLength);
  if (resultLength > SHA1_DIGEST_LENGTH) {
    resultLength = SHA1_DIGEST_LENGTH;
  }
  memcpy(result, sha, resultLength);

  // Zero out all internal data structures
  bzero(hashed_key, sizeof(hashed_key));
  bzero(sha, sizeof(sha));
  bzero(tmp_key, sizeof(tmp_key));
}

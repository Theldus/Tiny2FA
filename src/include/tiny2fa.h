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
 */

#ifndef TINY2FA_H
#define TINY2FA_H

	#include <stdint.h>

	/* Secret key size, in bytes. */
	#define T2_SECRET_KEY_SIZE 20
	
	/* Time padded size, in bytes. */
	#define T2_TIME_PADDED 8
	
	/* Interval for generating keys, in seconds. */
	#define T2_KEY_INTERVAL 30
	
	/* Amount of digits for the final key. */
	#define T2_TOTP_DIGITS 1000000
	
	/* Key length while encoded in base32. */
	#define T2_KEY_ENCODED_LENGTH 32
	
	/* Default window size. */
	#define T2_DEFAULT_WINDOW_SIZE 3

	/* -- External declarations. -- */

	/**
	 * Generates a secret key by a specified length.
	 *
	 * @param secret_key Secret-Key pointer, the pointer should have
	 * at least 33 bytes (32 + \0).
	 */
	extern void t2_generate_secret_key(uint8_t *secret_key);
	
	/**
	 * Gets the current key based in the base32 secret
	 * key passed by parameter and the reference time.
	 *
	 * @param b32_secret_key Your secret-key, generated by
	 * the method @m t2_generate_secret_key.
	 *
	 * @param tm target time in Unix Time Stamp, if 0, uses
	 * the current time.
	 *
	 * @return Returns the key equivalent for the current time
	 * and secret key.
	 *
	 * @see t2_generate_secret_key
	 */
	extern int t2_get_key(const uint8_t *b32_secret_key, uint64_t tm);
	
	/**
	 * Verifies a given base32 secret key through the key provided
	 * and a certain window.
	 *
	 * @param b32_secret_key Your secret-key, generated by
	 * the method @m generate_secret_key.
	 *
	 * @param key User provided key, this is the key to be checked.
	 *
	 * @param window Validation window. Passing 0 the default value
	 * (default = 3) will be used. With default value, will be
	 * generated 3 keys: before current time, current time and after.
	 * The key will be compared with these n-window keys and if one of
	 * them is equal to the key provided the function returns a non
	 * negative number and 0 otherwise.
	 *
	 * @return Returns a non-negative number if the key is valid and
	 * 0 otherwise.
	 */
	extern int t2_verify_key(const uint8_t *b32_secret_key, int key, int window);

#endif /* TINY2FA_H */

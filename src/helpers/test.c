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

#include <stdio.h>
#include <time.h>
#include <inttypes.h>
#include <tiny2fa.h>

/* Constant base32 key. */
const uint8_t b32_sk[T2_KEY_ENCODED_LENGTH + 1] = "A3WPD3B2SK5UNYCY7AI7ZMICC2LGDXQO";

/* Constant Unix Time Stamp. */
const uint64_t tm = 1546232290;

/* Constant for codes. */
const int correctCodes[] = {948759, 327634, 763856};

int main(int argc, char *argv[])
{
	((void)argc);
	((void)argv);

	int results[3];

	printf("\n ~~~~~~~~~~~~~~~~ Tiny2FA Tester ~~~~~~~~~~~~~~~~\n");
	printf("Using Secret-Key: %s\n", b32_sk);
	printf("Using time: %" PRIu64 "\n\n", tm);

	/* Tests get_key. */
	printf("Checking get_key\n");
	results[0] = t2_get_key(b32_sk, tm - T2_KEY_INTERVAL);
	results[1] = t2_get_key(b32_sk, tm);
	results[2] = t2_get_key(b32_sk, tm + T2_KEY_INTERVAL);

	printf("  > My previous code: %06d\n", results[0]);
	printf("  > My current  code: %06d\n", results[1]);
	printf("  > My future   code: %06d\n", results[2]);

	printf("Checking results...");
	if (results[0] == correctCodes[0] &&
		results[1] == correctCodes[1] &&
		results[2] == correctCodes[2])
	{
		printf(" [PASSED]\n");
		return (0);
	}
	else
	{
		printf(" [FAILED]\n");
		printf("Please check your system and if the error persists, contact us\n\n");
		return (-1);
	}

	return (0);
}

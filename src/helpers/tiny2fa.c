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
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>
#include <tiny2fa.h>

/* Program state. */
#define STATE_READ_ARGS            1
#define STATE_GET_KEY              2
#define STATE_GENERATE_SECRET_KEY  3
#define STATE_VERIFY_KEY_STEP1     4
#define STATE_VERIFY_KEY_STEP2     5
#define STATE_WINDOW               6
#define STATE_TIMESTAMP            7              

/* Program operations. */
#define OP_NOOP    0
#define OP_GET_KEY 1
#define OP_VEF_KEY 2


/* Program arguments. */
struct
{
	uint64_t timestamp;
	unsigned window;
	unsigned key;
	uint8_t sk[T2_KEY_ENCODED_LENGTH+1];
} args = {0};

/* Forward. */
void usage(int);

/**
 * No Operation.
 */
void noop(void){}

/**
 * Get Key.
 */
void get_key(void)
{
	uint64_t tm;  /* Work time.     */
	int offset;   /* Window offset. */
	
	/* Read time. */
	if (args.timestamp > 0)
		tm = args.timestamp;
	else
		tm = time(NULL);

	/* Check window amount. */
	if (args.window <= 1)
	{
		if (strlen((char *)args.sk) != T2_KEY_ENCODED_LENGTH)
		{
			fprintf(stderr, "Tiny2FA: Your key must be a valid base32 value"
				" with 32 characters!\n");
			usage(-1);
		}
		printf("%06d\n", t2_get_key(args.sk, tm));
	}
	else
	{
		/* Checks window. */
		if (!(args.window & 1))
		{
			fprintf(stderr, "Tiny2FA: Your window must be an odd number!\n");
			usage(-1);
		}

		/* Checks key. */
		if (strlen((char *)args.sk) != T2_KEY_ENCODED_LENGTH)
		{
			fprintf(stderr, "Tiny2FA: Your key must be a valid base32 value"
				" with 32 characters!\n");
			usage(-1);
		}

		/* Calculates the keys through multiple windows. */
		offset = -((args.window-1)/2);
		for (unsigned i = 0; i < args.window; i++)
		{
			uint64_t iter_time = tm + (offset * T2_KEY_INTERVAL);
			printf("W #%d: %06d - time: %" PRIu64 "\n", i,
				t2_get_key(args.sk, iter_time), iter_time);
			
			offset++;
		}
	}
}

/**
 * Verify gey.
 */
void verify_key(void)
{
	unsigned window;  /* Window amount. */
	int valid;        /* Key valid?.    */

	/* Check window amount. */
	if (!args.window)
		window = T2_DEFAULT_WINDOW_SIZE;
	else if (!(args.window & 1))
	{
		fprintf(stderr, "Tiny2FA: Your window must be an odd number!\n");
		usage(-1);
	}

	/* Set window. */
	window = args.window;

	/* Checks key. */
	if (strlen((char *)args.sk) != T2_KEY_ENCODED_LENGTH)
	{
		fprintf(stderr, "Tiny2FA: Your key must be a valid base32 value"
			" with 32 characters!\n");
		usage(-1);
	}

	valid = t2_verify_key(args.sk, args.key, window);
	printf("K: %06d: %s\n", args.key, (valid) ? "true" : "false");

	exit(valid);
}

/**
 * Generates a secret key.
 */
void generate_sk(void)
{
	uint8_t sk[T2_KEY_ENCODED_LENGTH+1];
	t2_generate_secret_key(sk);
	printf("%s\n", sk);
}

/**
 * Program usage.
 */
void usage(int retcode)
{
	printf("Usage: tiny2fa [options]\n");
	printf("Options: \n");
	printf("  -g, --generate-secret-key    Randomly generates the secret key in base32\n");
	printf("                               and outputs to the stdout.\n\n");

	printf("  -k, --get-key <secret-key>   Gets the current key based in the secret key\n");
	printf("                               options -t and -w can also be used together.\n\n");

	printf("  -t, --time-stamp <time>      Sets the unix time-stamp that will be used.\n");
	printf("                               This option should be used in conjunction\n");
	printf("                               with -k.\n\n");

	printf("  -w, --window <window>        Sets the window that will be used. Window\n");
	printf("                               values should be odd. This option should\n");
	printf("                               be used in conjunction with -k or -vy.\n\n");

	printf("  -vy, --verify <secret-key> <key> Verifies the the secret-key together\n");
	printf("                               with the key passed as parameter. Options\n");
	printf("                               and -w can be used in conjunction.\n\n");

	printf("  -h, --help                   This menu\n");
	printf("  -v, --version                Shows the program version\n");
	exit(retcode);
}

/**
 * Program version.
 */
void version(void)
{
	printf("Tiny2FA v1.0\n");
	printf("MIT License - Copyright (c) 2018 Davidson Francis\n\n");
	printf("This program contains parts of 'google-authenticator-libpam' project that\n");
	printf("is licensed under Apache v2 license, the license can be found in\n");
	printf("include/google_pam/LICENSE file.\n");
	exit(0);
}

/* Program operations. */
void (*prog_op[3])(void) = {noop, get_key, verify_key};

/**
 * Parses the command-line arguments.
 */
void readargs(int argc, char **argv)
{
	char *arg;  /* Current argument. */
	int state;  /* Current state.    */
	int op;     /* Operation.        */

	state = STATE_READ_ARGS;
	op = OP_NOOP;

	for (int i = 1; i < argc; i++)
	{
		arg = argv[i];

		if (state == STATE_READ_ARGS)
		{
			if (!strcmp(arg, "-h") || !strcmp(arg, "--help"))
				usage(0);

			else if (!strcmp(arg, "-v") || !strcmp(arg, "--version"))
				version();

			else if (!strcmp(arg, "-g") || !strcmp(arg, "--generate-secret-key"))
			{
				state = STATE_GENERATE_SECRET_KEY;
				generate_sk();
				break;
			}

			else if (!strcmp(arg, "-k") || !strcmp(arg, "--get-key"))
				state = STATE_GET_KEY;

			else if (!strcmp(arg, "-t") || !strcmp(arg, "--time-stamp"))
				state = STATE_TIMESTAMP;

			else if (!strcmp(arg, "-w") || !strcmp(arg, "--window"))
				state = STATE_WINDOW;

			else if (!strcmp(arg, "-vy") || !strcmp(arg, "--verify"))
				state = STATE_VERIFY_KEY_STEP1;

			else
			{
				fprintf(stderr, "Tiny2FA: Option '%s' not recognized!\n", arg);
				usage(-1);
			}
		}

		/**
		 * Get key state, the first argument after get-key
		 * should be the secret-key, so lets read.
		 */
		else if (state == STATE_GET_KEY)
		{
			strncpy((char *)args.sk, arg, T2_KEY_ENCODED_LENGTH);
			args.sk[T2_KEY_ENCODED_LENGTH] = '\0';
			state = STATE_READ_ARGS;
			op = OP_GET_KEY;
		}

		/**
		 * Get the timestamp arg.
		 */
		else if (state == STATE_TIMESTAMP)
		{
			args.timestamp = atoi(arg);
			state = STATE_READ_ARGS;
		}

		/**
		 * Get the window.
		 */
		else if (state == STATE_WINDOW)
		{
			args.window = atoi(arg);
			state = STATE_READ_ARGS;
		}

		/**
		 * Verify key
		 */
		else if (state == STATE_VERIFY_KEY_STEP1)
		{
			strncpy((char *)args.sk, arg, T2_KEY_ENCODED_LENGTH);
			args.sk[T2_KEY_ENCODED_LENGTH] = '\0';
			state = STATE_VERIFY_KEY_STEP2;
			op = OP_VEF_KEY;
		}
		else if (state == STATE_VERIFY_KEY_STEP2)
		{
			args.key = atoi(arg);
			state = STATE_READ_ARGS;
		}
	}

	/* Do operation. */
	(*prog_op[op])();
}

/**
 * Program main.
 */
int main(int argc, char *argv[])
{
	if (argc < 2)
		usage(-1);

	readargs(argc, argv);
	return (0);
}

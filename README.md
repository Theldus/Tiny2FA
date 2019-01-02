## Tiny2FA [![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
A small C library that implements TOTP, compatible with Google Authenticator

### Library
Tiny2FA is a small C library that implements TOTP. The project was mainly based in the
[google-authenticator-libpam](https://github.com/google/google-authenticator-libpam/blob/master/src/pam_google_authenticator.c)
project and a nice tutorial found [here](https://www.codementor.io/slavko/google-two-step-authentication-otp-generation-du1082vho).
Although the Google's libpam project is very nice, I would like to have a very tiny library that I could use just calling a
few functions, without much to think about.

The library is capable of generating secret-keys, generate 6-digit code and verify the validity of the entered code.
It's also possible to adjust time-stamps and window time-slice.

### Usage
All the core is divided into just 3 functions: `t2_generate_secret_key`, `t2_get_key` and `t2_verify_key`:
```c
void t2_generate_secret_key(uint8_t *secret_key);
```
t2_generate_secret_key generates a base32 secret key and save in the buffer passed as parameter.

```c
int t2_get_key(const uint8_t *b32_secret_key, uint64_t tm);
```
t2_get_key gets the current key (6 digits) based in the secret_key and the time (in seconds, unix
time stamp) tm passed as parameter. Note that if you want to use the current time, just pass 0 to
tm and the function will use the current time instead of the parameter.

```c
int t2_verify_key(const uint8_t *b32_secret_key, int key, int window);
```
t2_verify_key expects 3 arguments: base32 secret key, code and window. The window is not necessary
at all, it just lets you to choose a window different from the default (if argument eq 0, the function will use the
default value, that is equal 3). The window allows you to do a fine tune in how much time you want that the
verifier will consider your code. Actually the time is always 30 seconds, but a bigger window will make the code
to generate keys in the future and in the past (in steps of 30s) in order to find the key that the other device
have generated.

#### Example
```c
/* Build with: gcc program.c -o program -l2fa, no magic. */
#include <stdio.h>
#include <tiny2fa.h>

int main()
{
	uint8_t b32_key[32 + 1];
	int code;

	/* Get the base 32 secret key. */
	t2_generate_secret_key(b32_key);
	
	printf("Your secret key is: %s\n", b32_key);
	printf("Add the key to your device and enter below the verification code: ");

	/* Read key. */
	scanf("%d", &code);
	
	/* Validates the code. */
	while ( !t2_verify_key(b32_key, code, 0) )
	{
		printf("The key entered is wrong, try again\n");
		scanf("%d", &code);
	}

	printf("Valid key =)\n");
	return (0);
}
```

For more info, read the man pages available and in the latter case, the source (tiny2fa.{c,h}), I think it's simple
enough for anyone read, ;-). I also encourage you to create issues if desired.

### Program
In addition to the library, the project also features a program with the same name that handles 2FA/TOTP in many ways,
both to show library usage and to allow library use without the need to write programs, choose the most convenient.
```
Usage: tiny2fa [options]
Options: 
  -g, --generate-secret-key           Randomly generates the secret key in base32 and outputs to the stdout.

  -k, --get-key <secret-key>          Gets the current key based in the secret key options -t and -w can
                                      also be used together.

  -t, --time-stamp <time>             Sets the unix time-stamp that will be used. This option should be used
                                      in conjunction with -k.

  -w, --window <window>               Sets the window that will be used. Window values should be odd. This
                                      option should be used in conjunction with -k or -vy.

  -vy, --verify <secret-key> <key>    Verifies the the secret-key together with the key passed as parameter.
                                      Options and -w can be used in conjunction.

  -h, --help                          This menu
  -v, --version                       Shows the program version
```
So Tiny2FA can also be useful for scripts languages, ;-).

### Installing/Building
Tiny2FA is written in ISO C and just requires that the target system have the LIB C available; maybe the makefile
is somehow limited to Unix-like systems but still very capable to build in other environments. If you're facing
issues with this, contact me.

Anyway, the building process is as follows:
```bash
$ cd src/
$ make all
$ sudo make install
```
### License
Tiny2FA is licensed under the MIT License, but this project also contains parts of 'google-authenticator-libpam'
project that is licensed under Apache v2 license. See [caf80cf](https://github.com/Theldus/Tiny2FA/commit/caf80cf86ec2760b55da44cee37b309e6810cb7a)
and [here](https://github.com/Theldus/Tiny2FA/tree/master/src/include/google_pam) for more details.

----------------------------
That's it, if you liked, found a bug or wanna contribute, let me know, ;-).

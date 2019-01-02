# MIT License
#
# Copyright (c) 2018 Davidson Francis <davidsondfgl@gmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

CC=gcc
AR=ar
INCLUDE       = $(CURDIR)/include
INCLUDE_LIBS  = $(INCLUDE)/google_pam
CFLAGS        = -Wall -Wextra -Werror -Wpedantic
CFLAGS       += -I $(INCLUDE_LIBS) -I $(INCLUDE) -std=c99
ARFLAGS       = cru
LIB           = lib2fa.a
TEST          = $(CURDIR)/helpers/test.o
TINY2FA       = $(CURDIR)/helpers/tiny2fa.o
TINY2FA_BIN   = $(CURDIR)/helpers/tiny2fa

# Prefix
ifeq ($(PREFIX),)
    PREFIX := /usr/local
endif

# Detect machine type
MACHINE := $(shell uname -m)
ifeq ($(MACHINE), x86_64)
	LIBDIR = $(PREFIX)/lib64
else
	LIBDIR = $(PREFIX)/lib
endif

# Conflicts
.PHONY: all
.PHONY: lib
.PHONY: test
.PHONY: tiny2fa
.PHONY: install
.PHONY: uninstall	
.PHONY: tiny2fa.pc
.PHONY: clean	

# Paths
INCDIR = $(PREFIX)/include
BINDIR = $(PREFIX)/bin
MANDIR = $(PREFIX)/man
PKGDIR = $(LIBDIR)/pkgconfig

# Library
LIB_C_SRC = $(wildcard *.c)

LIB_OBJ   = $(LIB_C_SRC:.c=.o)

%.o: %.c
	$(CC) $< $(CFLAGS) -c -o $@

# All rules
all: lib test tiny2fa

# Library rules
lib: $(LIB_OBJ)
	$(AR) $(ARFLAGS) $(LIB) $^

# Test rules
test: $(TEST)
	$(CC) $< $(CFLAGS) -o helpers/$@ $(LIB)
	@helpers/test

# Tiny2FA Helper rules
tiny2fa: $(TINY2FA)
	$(CC) $< $(CFLAGS) -o helpers/$@ $(LIB)

# Install rules
install: $(LIB) $(TINY2FA_BIN) tiny2fa.pc
	@#Library
	install -d $(DESTDIR)$(LIBDIR)
	install -m 644 $(LIB) $(DESTDIR)$(LIBDIR)
	@#Headers
	install -d $(DESTDIR)$(INCDIR)/google_pam
	install -m 644 $(INCLUDE)/*.h $(DESTDIR)$(INCDIR)
	install -m 644 $(INCLUDE)/google_pam/*.h $(DESTDIR)$(INCDIR)/google_pam
	install -m 644 $(INCLUDE)/google_pam/LICENSE $(DESTDIR)$(INCDIR)/google_pam
	@#Binary file
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(TINY2FA_BIN) $(DESTDIR)$(BINDIR)
	@#Manpages
	install -d $(DESTDIR)$(MANDIR)/man1
	install -d $(DESTDIR)$(MANDIR)/man3
	install -m 0644 $(CURDIR)/man/man1/tiny2fa.1 $(DESTDIR)$(MANDIR)/man1/
	gzip $(DESTDIR)$(MANDIR)/man1/tiny2fa.1
	install -m 0644 $(CURDIR)/man/man3/t2_generate_secret_key.3 $(DESTDIR)$(MANDIR)/man3/
	gzip $(DESTDIR)$(MANDIR)/man3/t2_generate_secret_key.3
	install -m 0644 $(CURDIR)/man/man3/t2_get_key.3 $(DESTDIR)$(MANDIR)/man3/
	gzip $(DESTDIR)$(MANDIR)/man3/t2_get_key.3
	install -m 0644 $(CURDIR)/man/man3/t2_verify_key.3 $(DESTDIR)$(MANDIR)/man3/
	gzip $(DESTDIR)$(MANDIR)/man3/t2_verify_key.3

# Uninstall rules
uninstall:
	rm -f  $(DESTDIR)$(LIBDIR)/$(LIB)
	rm -rf $(DESTDIR)$(INCDIR)/google_pam
	rm -f  $(DESTDIR)$(INCDIR)/tiny2fa.h
	rm -f  $(DESTDIR)$(BINDIR)/tiny2fa
	rm -f  $(DESTDIR)$(MANDIR)/man1/tiny2fa.1.gz
	rm -f  $(DESTDIR)$(MANDIR)/man3/{t2_generate_secret_key.3.gz,t2_get_key.3.gz,t2_verify_key.3.gz}
	rm -f  $(DESTDIR)$(PKGDIR)/tiny2fa.pc

# Generate tiny2fa.pc
tiny2fa.pc:
	@install -d $(DESTDIR)$(PKGDIR)
	@echo 'prefix='$(DESTDIR)$(PREFIX)    >  $(DESTDIR)$(PKGDIR)/tiny2fa.pc
	@echo 'libdir='$(DESTDIR)$(LIBDIR)    >> $(DESTDIR)$(PKGDIR)/tiny2fa.pc
	@echo 'includedir=$${prefix}/include' >> $(DESTDIR)$(PKGDIR)/tiny2fa.pc
	@echo 'Name: Tiny2FA'                 >> $(DESTDIR)$(PKGDIR)/tiny2fa.pc
	@echo 'Description: Manages secret-keys and keys for 2FA - TOTP algorithm' >> $(DESTDIR)$(PKGDIR)/tiny2fa.pc
	@echo 'Version: 1.0'                  >> $(DESTDIR)$(PKGDIR)/tiny2fa.pc
	@echo 'Libs: -L$${libdir} -l2fa'       >> $(DESTDIR)$(PKGDIR)/tiny2fa.pc
	@echo 'Libs.private:'                 >> $(DESTDIR)$(PKGDIR)/tiny2fa.pc
	@echo 'Cflags: -I$${includedir} -I$${includedir}/google_pam' >> $(DESTDIR)$(PKGDIR)/tiny2fa.pc

# Clean rules
clean:
	rm -f $(LIB_OBJ)
	rm -f $(LIB)
	rm -f $(CURDIR)/helpers/test.o
	rm -f $(CURDIR)/helpers/test
	rm -f $(CURDIR)/helpers/tiny2fa.o
	rm -f $(CURDIR)/helpers/tiny2fa

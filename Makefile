EXEC = dnsx
CC = /usr/bin/gcc
TSOCKSLIB = tsocks
# If the program ever grows, we'll enjoy this macro:
SRCFILES := $(wildcard *.c)
OBJFILES := $(patsubst %.c,%.o,$(wildcard *.c))


# Build host specific additionals.  Uncomment whatever matches your situation.
# For BSD's with pkgsrc:
#EXTRA_CFLAGS = -I /usr/pkg/include -L /usr/pkg/lib
EXTRA_CFLAGS = -L $(realpath .)

# Hardening and warnings for building with gcc
GCCWARNINGS = -Wall -fno-strict-aliasing -W -Wfloat-equal -Wundef	\
-Wpointer-arith -Wstrict-prototypes -Wmissing-prototypes		\
-Wwrite-strings -Wredundant-decls -Wchar-subscripts -Wcomment		\
-Wformat=2 -Wwrite-strings -Wmissing-declarations -Wredundant-decls	\
-Wnested-externs -Wbad-function-cast -Wswitch-enum -Winit-self		\
-Wmissing-field-initializers -Wdeclaration-after-statement		\
-Wold-style-definition -Waddress -Wmissing-noreturn	\
-Wstrict-overflow=1 -Wextra -Warray-bounds		\
-Wstack-protector -Wformat -Wformat-security -Wpointer-sign
GCCHARDENING=-D_FORTIFY_SOURCE=2 -fstack-protector-all -fwrapv -fPIE --param ssp-buffer-size=1
LDHARDENING=-pie -z relro -z now

CFLAGS=-g -O2 $(EXTRA_CFLAGS) $(GCCHARDENING) $(GCCWARNINGS) 
LDFLAGS= $(LDHARDENING)


all: $(SRCFILES) libtsocks
	$(CC) $(CFLAGS) $(SRCFILES) -o $(EXEC) -l$(TSOCKSLIB) -L$(STAGING_DIR)/usr/lib

libtsocks:
	make -C lib/tsocks
	cp lib/tsocks/libtsocks.dylib* .

clean:
	rm -f $(OBJFILES) $(EXEC)
	rm -f libtsocks.dylib*
	rm -Rf dnsx.dSYM
	make clean -C lib/tsocks

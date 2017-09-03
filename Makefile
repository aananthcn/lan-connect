LFLAGS = -lssl -lcrypto -L/usr/local/opt/openssl/lib

ARGS   = GLOBAL_IFLAGS="${IFLAGS}" GLOBAL_LFLAGS="${LFLAGS}"

all:
	$(MAKE) -C ./test ${ARGS}

clean:
	$(MAKE) -C ./test clean

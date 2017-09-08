.DEFAULT_GOAL := all

# constants

CLASSPATH = ../../classes
MKDIR = mkdir -p
COPY = cp -r
CC = g++


LOCAL_IFLAGS = -I. -I${CLASSPATH}
LOCAL_CFLAGS = -Wall -g -std=c++11 ${LOCAL_IFLAGS}
LOCAL_LFLAGS = -std=c++11 -lssl -lcrypto -L/usr/local/opt/openssl/lib



# objects: that is compiler outputs
objects = 	LcFind.o \
			${CLASSPATH}/SecureSocket.o \
			${CLASSPATH}/LcFinder.o


%.o: %.cpp
	$(CC) -c $(LOCAL_CFLAGS) $^ -o $@



lc-finder: ${objects}
	$(CC) -o $@ $^ $(LOCAL_LFLAGS)


.PHONY: install clean


clean:
	$(RM) ${objects}
	$(RM) lc-finder


debug: LOCAL_CFLAGS += -g -DDEBUG
debug: LOCAL_LFLAGS += -g -DDEBUG
debug: lc-finder


all: lc-finder


.DEFAULT_GOAL := all

# constants

CLASSPATH = ../../classes
MKDIR = mkdir -p
COPY = cp -r
CC = g++


LOCAL_IFLAGS = -I. -I${CLASSPATH}
LOCAL_CFLAGS = -Wall -g -std=c++11 ${LOCAL_IFLAGS}
LOCAL_LFLAGS = -g -std=c++11 -lssl -lcrypto -L/usr/local/opt/openssl/lib -ljansson



# objects: that is compiler outputs
objects = 	EasyJsonApp.o \
			${CLASSPATH}/EasyJson.o


%.o: %.cpp
	$(CC) -c $(LOCAL_CFLAGS) $^ -o $@



lc-easyjson: ${objects}
	$(CC) -o $@ $^ $(LOCAL_LFLAGS)


.PHONY: install clean


clean:
	$(RM) ${objects}
	$(RM) lc-easyjson


debug: LOCAL_CFLAGS += -g -DDEBUG
debug: LOCAL_LFLAGS += -g -DDEBUG
debug: lc-easyjson


all: lc-easyjson


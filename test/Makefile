.DEFAULT_GOAL := all

# constants

MKDIR = mkdir -p
COPY = cp -r
CC = g++


LOCAL_IFLAGS = -I. -I../classes
LOCAL_CFLAGS = -Wall -g -std=c++11 ${LOCAL_IFLAGS} ${GLOBAL_IFLAGS}
LOCAL_LFLAGS = -std=c++11 ${GLOBAL_LFLAGS}



# objects: that is compiler outputs
client_objects = 	Client.o \
					../classes/SecureSocket.o \


server_objects = 	Server.o \
					../classes/SecureSocket.o \


%.o: %.cpp
	$(CC) -c $(LOCAL_CFLAGS) $^ -o $@



lc-client: ${client_objects}
	$(CC) -o $@ $^ $(LOCAL_LFLAGS)

lc-server: ${server_objects}
	$(CC) -o $@ $^ $(LOCAL_LFLAGS)


.PHONY: install clean


clean:
	$(RM) ${client_objects} ${server_objects}
	$(RM) lc-client lc-server


debug: LOCAL_CFLAGS += -g -DDEBUG
debug: LOCAL_LFLAGS += -g -DDEBUG
debug: lc-server lc-client


all: lc-client lc-server


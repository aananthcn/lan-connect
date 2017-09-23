.DEFAULT_GOAL := all

# constants

CLASSPATH = ../../classes
MKDIR = mkdir -p
COPY = cp -r
CC = g++


IFLAGS = -I. -I${CLASSPATH}
CFLAGS = -Wall -g -std=c++11 ${IFLAGS}
LFLAGS = -g -std=c++11 -lssl -lcrypto -L/usr/local/opt/openssl/lib -ljansson


# Final binary name
BIN = 	lc-link

# List of all .cpp source files.
SRC = 	LcLinkApp.cpp \
		$(wildcard ${CLASSPATH}/*.cpp)

# All .o files go to build dir.
OBJ = 	$(SRC:%.cpp=%.o)

# Gcc/Clang will create these .d files containing dependencies.
DEP = 	$(OBJ:%.o=%.d)

# Link all object files
$(BIN) : $(OBJ)
	$(CC) $(LFLAGS) $^ -o $@

-include $(DEP)

# Build target for every single object file.
# The potential dependency on header files is covered
# by calling `-include $(DEP)`.
%.o : %.cpp
	# The -MMD flags additionaly creates a .d file with
	# the same name as the .o file.
	$(CC) $(CFLAGS) -MMD -c $< -o $@

.PHONY : clean


.PHONY : clean
clean :
	# This should remove all generated files.
	-rm $(BIN) $(OBJ) $(DEP)

all : $(BIN)
# Compiler
CC     = gcc
CFLAGS = -g -O2 $(LIBS)
LFLAGS  = \
	/usr/local/lib/libirs.a \
	/usr/local/lib/libdns.a \
	/usr/local/lib/libisccfg.a \
	/usr/local/lib/libisc.a
LIBS = -lcrypto -lpthread -lxml2 -lgssapi_krb5 -lkrb5
INCLUDES = \
	-D_GNU_SOURCE \
	-I /usr/include/libxml2

MKBIN   = mkdir -p $(BIN)
MKBUILD = mkdir -p $(BUILD)

# Directory Structure
BIN   = bin/
BUILD = build/
SRC   = src/

# Object Files
_OBJ =\
	resolve.o
OBJ  = $(patsubst %,$(BUILD)%,$(_OBJ))

# Dependencies
DEPS = $(OBJ:.o=.d)

# Main
MAIN = main

# Build executable
.PHONY: default
default: mkdir $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) $(LFLAGS) $(LIBS) -o $(BIN)$(MAIN)

-include $(DEPS)

# Build object files
$(BUILD)%.o: $(SRC)%.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -MMD -MF $(@:.o=.d) -o $@

# Run program
.PHONY: run
run:
	./$(BIN)$(MAIN)

# Build directory structure
.PHONY: mkdir
mkdir:
	$(MKBIN)
	$(MKBUILD)

# Clean up object files
.PHONY: clean
clean:
	$(RM) -r $(BUILD)
	$(RM) -r *~

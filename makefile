# Compiler
CC     = gcc
CFLAGS = -g -O2 $(LIBS)
LFLAGS  = \
	/usr/lib/libirs.so \
	/usr/lib/libdns.so \
	/usr/lib/libisccfg.so \
	/usr/lib/libisc.so \
	/usr/lib/libxml2.so \
	/usr/lib/libmysqlclient.so
LIBS = -lcrypto -lpthread -lxml2 -lgssapi_krb5 -lkrb5
INCLUDES = \
	-D_GNU_SOURCE \
	-I include

MKBIN   = mkdir -p $(BIN)
MKBUILD = mkdir -p $(BUILD)

# Directory Structure
BIN   = bin/
BUILD = build/
SRC   = src/
TEST = test/

# Object Files
_OBJ =\
	main.o \
	resolve.o \
	helper.o
OBJ  = $(patsubst %,$(BUILD)%,$(_OBJ))

# Test Files
_CUNIT =\
	resolve.o \
	helper.o \
	test_resolve.o
CUNIT  = $(patsubst %,$(BUILD)%,$(_CUNIT))

# Dependencies
DEPS = $(OBJ:.o=.d)
CUNIT_DEPS = $(OBJ:.o=.d)

# Main
MAIN = main
MAIN_TEST = test

# Build executable
.PHONY: default
default: mkdir $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) $(LFLAGS) $(LIBS) -o $(BIN)$(MAIN)

-include $(DEPS)

# Build object files
$(BUILD)%.o: $(SRC)%.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -MMD -MF $(@:.o=.d) -o $@


# Compile test
.PHONY: $(MAIN_TEST)
$(MAIN_TEST): default mkdir $(CUNIT)
	$(CC) $(CFLAGS) $(CUNIT) $(LFLAGS) -lcunit $(LIBS) -o $(BIN)$(MAIN_TEST)

-include $(CUNIT_DEPS)

# Build test files
$(BUILD)%.o: $(TEST)%.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -MMD -MF $(@:.o=.d) -o $@


# Run program
.PHONY: run
run:
	./$(BIN)$(MAIN)

# Run program
.PHONY: trun
trun:
	./$(BIN)$(MAIN_TEST)

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

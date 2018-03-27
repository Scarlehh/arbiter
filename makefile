# Compiler
CC     = gcc
CFLAGS = -g -O2
LFLAGS  = \
	/usr/lib/libldns.so \
	/usr/lib/libmysqlclient.so

LIBS = -lcrypto -lpthread
INCLUDES = \
	-I include

MKBIN   = mkdir -p $(BIN)
MKBUILD = mkdir -p $(BUILD)

# Directory Structure
BIN   = bin/
BUILD = build/
SRC   = src/
TEST = test/
UTIL = util/

# Main Files
_OBJ_RES =\
	ldns.o \
	resolver.o \
	helper.o
OBJ_RES  = $(patsubst %,$(BUILD)%,$(_OBJ_RES))

# Test Files
_OBJ_TEST_RES =\
	test_resolve.o \
	resolver.o \
	helper.o
OBJ_TEST_RES  = $(patsubst %,$(BUILD)%,$(_OBJ_TEST_RES))

# Util Files
_OBJ_UTIL =\
	ecdsa.o
OBJ_UTIL  = $(patsubst %,$(BUILD)%,$(_OBJ_UTIL))

# Dependencies
DEPS_RES = $(OBJ_RES:.o=.d)
DEPS_TEST_RES = $(OBJ_TEST_RES:.o=.d)
DEPS_TEST_RES = $(OBJ_UTIL:.o=.d)

# Main
MAIN_RES = main
MAIN_TEST_RES = test
MAIN_UTIL = util


.PHONY: default
default: $(MAIN_RES) $(MAIN_TEST_RES) $(MAIN_UTIL)

# Resolver
.PHONY: $(MAIN_RES)
$(MAIN_RES): mkdir $(OBJ_RES)
	$(CC) $(CFLAGS) $(OBJ_RES) $(LFLAGS) $(LIBS) -o $(BIN)$(MAIN_RES)

-include $(DEPS_RES)


# Test resolver
.PHONY: $(MAIN_TEST_RES)
$(MAIN_TEST_RES): mkdir $(MAIN_RES) $(OBJ_TEST_RES)
	$(CC) $(CFLAGS) $(OBJ_TEST_RES) $(LFLAGS) $(LIBS) -lcunit -o $(BIN)$(MAIN_TEST_RES)

-include $(DEPS_TEST_RES)


# Util
.PHONY: $(MAIN_UTIL)
$(MAIN_UTIL): mkdir $(OBJ_UTIL)
	$(CC) $(CFLAGS) $(OBJ_UTIL) -lcrypto -o $(BIN)$(MAIN_UTIL)

-include $(DEPS_UTL)


# Build src files
$(BUILD)%.o: $(SRC)%.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -MMD -MF $(@:.o=.d) -o $@

# Build test files
$(BUILD)%.o: $(TEST)%.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -MMD -MF $(@:.o=.d) -o $@

# Build util files
$(BUILD)%.o: $(UTIL)%.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -MMD -MF $(@:.o=.d) -o $@


# Run main
.PHONY: mrun
mrun:
	./$(BIN)$(MAIN_RES)

# Run test resolver
.PHONY: trun
trun:
	./$(BIN)$(MAIN_TEST_RES)

# Run test resolver
.PHONY: urun
urun:
	./$(BIN)$(MAIN_UTIL)


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

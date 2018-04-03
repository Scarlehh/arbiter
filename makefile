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
	resolve.o \
	helper.o
OBJ_RES  = $(patsubst %,$(BUILD)%,$(_OBJ_RES))

# Test Files
_OBJ_TEST_RES =\
	test_resolve.o \
	resolve.o \
	helper.o
OBJ_TEST_RES  = $(patsubst %,$(BUILD)%,$(_OBJ_TEST_RES))

# Req size Files
_OBJ_REQSIZE =\
	reqsize.o
OBJ_REQSIZE  = $(patsubst %,$(BUILD)%,$(_OBJ_REQSIZE))

# Util Files
_OBJ_UTIL =\
	ecdsa.o
OBJ_UTIL  = $(patsubst %,$(BUILD)%,$(_OBJ_UTIL))

# Dependencies
DEPS_RES = $(OBJ_RES:.o=.d)
DEPS_TEST_RES = $(OBJ_TEST_RES:.o=.d)
DEPS_REQSIZE = $(OBJ_REQSIZE:.o=.d)
DEPS_UTIL = $(OBJ_UTIL:.o=.d)

# Main
MAIN_RES = main
MAIN_TEST_RES = test
MAIN_REQSIZE = reqsize
MAIN_UTIL = util


.PHONY: default
default: $(MAIN_RES) $(MAIN_TEST_RES) $(MAIN_REQSIZE) $(MAIN_UTIL)

# Resolver
.PHONY: $(MAIN_RES)
$(MAIN_RES): mkdir $(OBJ_RES)
	$(CC) $(CFLAGS) $(OBJ_RES) $(LFLAGS) $(LIBS) -o $(BIN)$@

-include $(DEPS_RES)


# Test resolver
.PHONY: $(MAIN_TEST_RES)
$(MAIN_TEST_RES): mkdir $(MAIN_RES) $(OBJ_TEST_RES)
	$(CC) $(CFLAGS) $(OBJ_TEST_RES) $(LFLAGS) $(LIBS) -lcunit -o $(BIN)$@

-include $(DEPS_TEST_RES)


# Req size
.PHONY: $(MAIN_REQSIZE)
$(MAIN_REQSIZE): mkdir $(OBJ_REQSIZE)
	$(CC) $(CFLAGS) $(OBJ_REQSIZE) -o $(BIN)$@

-include $(DEPS_REQSIZE)


# Util
.PHONY: $(MAIN_UTIL)
$(MAIN_UTIL): mkdir $(OBJ_UTIL)
	$(CC) $(CFLAGS) $(OBJ_UTIL) -lcrypto -o $(BIN)$@

-include $(DEPS_UTIL)


# Builders
$(BUILD)%.o: $(SRC)%.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -MMD -MF $(@:.o=.d) -o $@

$(BUILD)%.o: $(TEST)%.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -MMD -MF $(@:.o=.d) -o $@

$(BUILD)%.o: $(UTIL)%.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -MMD -MF $(@:.o=.d) -o $@


# Runners
.PHONY: mrun
mrun:
	./$(BIN)$(MAIN_RES)

.PHONY: trun
trun:
	./$(BIN)$(MAIN_TEST_RES)

.PHONY: rrun
rrun:
	./$(BIN)$(MAIN_REQSIZE)

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

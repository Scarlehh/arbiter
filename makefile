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

# Main Files
_OBJ_RES =\
	ldns.o \
	resolve.o \
	helper.o
OBJ_RES  = $(patsubst %,$(BUILD)%,$(_OBJ_RES))

# Req size Files
_OBJ_REQSIZE =\
	reqsize.o \
	resolve.o \
	helper.o
OBJ_REQSIZE  = $(patsubst %,$(BUILD)%,$(_OBJ_REQSIZE))

# Dependencies
DEPS_RES = $(OBJ_RES:.o=.d)
DEPS_REQSIZE = $(OBJ_REQSIZE:.o=.d)

# Main
MAIN_RES = main
MAIN_REQSIZE = reqsize


.PHONY: default
default: $(MAIN_RES) $(MAIN_TEST_RES) $(MAIN_REQSIZE) $(MAIN_UTIL)

# Resolver
.PHONY: $(MAIN_RES)
$(MAIN_RES): mkdir $(OBJ_RES)
	$(CC) $(CFLAGS) $(OBJ_RES) $(LFLAGS) $(LIBS) -o $(BIN)$@

-include $(DEPS_RES)

# Req size
.PHONY: $(MAIN_REQSIZE)
$(MAIN_REQSIZE): mkdir $(OBJ_REQSIZE)
	$(CC) $(CFLAGS) $(OBJ_REQSIZE) $(LFLAGS) $(LIBS) -o $(BIN)$@

-include $(DEPS_REQSIZE)


# Builders
$(BUILD)%.o: $(SRC)%.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -MMD -MF $(@:.o=.d) -o $@


# Runners
.PHONY: mrun
mrun:
	./$(BIN)$(MAIN_RES)

.PHONY: rrun
rrun:
	./$(BIN)$(MAIN_REQSIZE)


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
	$(RM) -r py/venv/

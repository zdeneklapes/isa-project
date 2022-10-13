###############################################################################
# Makefile
# Řešení ISA-PROJEKT
# Datum: 2022-10-13
# Autor: Zdenek Lapes <lapes.zdenek@gmail.com> (xlapes02), FIT
###############################################################################


###############################################################################
###                             MAKEFILE VARIABLES                          ###
###############################################################################
RM = rm -f
LOGIN = xlapes02

SENDER = sender
RECEIVER = receiver

CC = gcc
CFLAGS = -g -std=gnu99 -Wall -Wextra -Werror -pedantic -pthread
CFLAGS += -O0

SRC_SENDER_DIR := src/sender
OBJ_SENDER_DIR := src/sender/obj

SRC_RECEIVER_DIR := src/receiver
OBJ_RECEIVER_DIR := src/receiver/obj


SRC_SENDER_FILES := $(wildcard $(SRC_SENDER_DIR)/*.c)
OBJ_SENDER_FILES := $(patsubst $(SRC_SENDER_DIR)/%.c,$(OBJ_SENDER_DIR)/%.o,$(SRC_SENDER_FILES))

SRC_RECEIVER_FILES := $(wildcard $(SRC_RECEIVER_DIR)/*.c)
OBJ_RECEIVER_FILES := $(patsubst $(SRC_RECEIVER_DIR)/%.c,$(OBJ_RECEIVER_DIR)/%.o,$(SRC_RECEIVER_FILES))


###############################################################################
###                            PROGRAM COMPILING                            ###
###############################################################################
# Compile all sender and receiver
all: $(SENDER) $(RECEIVER)


# Create sender exe file in root dir
$(SENDER): $(OBJ_SENDER_FILES)
	$(CC) $(CFLAGS) -o $@ $^

# Create objective files and output dir is OBJ_SENDER_DIR
$(OBJ_SENDER_DIR)/%.o: $(SRC_SENDER_FILES)
	$(CC) $(CFLAGS) -c -o $@ $<

# Create receiver exe file in root dir
$(RECEIVER): $(OBJ_RECEIVER_FILES)
	$(CC) $(CFLAGS) -o $@ $^

# Create objective files and output dir is OBJ_RECEIVER_DIR
$(OBJ_RECEIVER_DIR)/%.o: $(SRC_RECEIVER_FILES)
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: docs
docs:
	echo "TODO"


###############################################################################
###                                  DELETE                                 ###
###############################################################################
.PHONY: clean
clean:
	$(RM) $(SENDER) $(RECEIVER) $(OBJ_SENDER_FILES) $(OBJ_RECEIVER_FILES) xlapes02.zip

###############################################################################
###                                    RUN                                  ###
###############################################################################
.PHONY: run
run: $(SENDER) $(RECEIVER)
	echo "TODO"


.PHONY: run_sender
run_sender: $(SENDER)
	./$(SENDER) -u 127.0.0.1 example.com data.txt ./data.txt


.PHONY: run_receiver
run_receiver: $(RECEIVER))
	echo "TODO"

###############################################################################
###                                   ZIP                                   ###
###############################################################################
# TODO: Can be source files inside src folder
.PHONY: zip
zip: clean docs
	zip -r $(LOGIN).zip sender receiver Makefile manual.pdf README.md









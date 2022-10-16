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

SRC_SENDER_DIR := sender
OBJ_SENDER_DIR := sender/obj

SRC_RECEIVER_DIR := receiver
OBJ_RECEIVER_DIR := receiver/obj

SRC_COMMON_DIR := common
OBJ_COMMON_DIR := common/obj

SRC_SENDER_FILES := $(wildcard $(SRC_SENDER_DIR)/*.c)
SRC_RECEIVER_FILES := $(wildcard $(SRC_RECEIVER_DIR)/*.c)
SRC_COMMON_FILES := $(wildcard $(SRC_COMMON_DIR)/*.c)

#OBJ_SENDER_FILES := $(patsubst $(SRC_SENDER_DIR)/%.c,$(OBJ_SENDER_DIR)/%.o,$(SRC_SENDER_FILES))
#OBJ_RECEIVER_FILES := $(patsubst $(SRC_RECEIVER_DIR)/%.c,$(OBJ_RECEIVER_DIR)/%.o,$(SRC_RECEIVER_FILES))
#OBJ_COMMON_FILES := $(patsubst $(SRC_COMMON_DIR)/%.c,$(OBJ_COMMON_DIR)/%.o,$(SRC_COMMON_FILES))

###############################################################################
###                            PROGRAM COMPILING                            ###
###############################################################################
# Compile all sender and receiver
all: $(SENDER) $(RECEIVER)

.PHONY: $(SENDER)
$(SENDER): $(SRC_SENDER_FILES) $(SRC_COMMON_FILES)
	$(CC) $(CFLAGS) -o dns_$@ $^

.PHONY: $(RECEIVER)
$(RECEIVER): $(SRC_RECEIVER_FILES) $(SRC_COMMON_FILES)
	$(CC) $(CFLAGS) -o dns_$@ $^

.PHONY: docs
docs:
	echo "TODO"


###############################################################################
###                                  DELETE                                 ###
###############################################################################
.PHONY: clean
clean:
	$(RM) dns_$(SENDER) dns_$(RECEIVER) xlapes02.zip
	$(RM) -rd *.dSYM .pytest_cache
# $(OBJ_SENDER_FILES) $(OBJ_RECEIVER_FILES) $(OBJ_COMMON_FILES)


###############################################################################
###                                    RUN                                  ###
###############################################################################
.PHONY: run
run: $(SENDER) $(RECEIVER)
	echo "TODO"


.PHONY: run_sender
run_sender: $(SENDER)
	./dns_$(SENDER) example.com data/input1.txt ./output1.txt
	#./dns_$(SENDER) -u 127.0.0.1 example.com data/input1.txt ./output1.txt

.PHONY: run_sender
run_sender_macos: $(SENDER)
	./dns_$(SENDER) -u 0.0.0.0 example.com data/input1.txt ./output1.txt
	#./dns_$(SENDER) -u 127.0.0.1 example.com data/input1.txt ./output1.txt


.PHONY: run_receiver
run_receiver: $(RECEIVER)
	./dns_$(RECEIVER) example.com ./data

###############################################################################
###                                   ZIP                                   ###
###############################################################################
# TODO: Can be source files inside src folder
.PHONY: zip
zip: clean docs
	zip -r $(LOGIN).zip sender receiver common Makefile manual.pdf README.md









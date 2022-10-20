###############################################################################
# Makefile
# Řešení ISA-PROJEKT
# Datum: 2022-10-20
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
CFLAGS = -g -std=gnu99 -Wall -Wextra -Werror -pedantic
CFLAGS += -O0

SRC_SENDER_FILES := $(wildcard sender/*.c)
SRC_RECEIVER_FILES := $(wildcard receiver/*.c)
SRC_COMMON_FILES := $(wildcard common/*.c)



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



###############################################################################
###                            		OTHERS                                  ###
###############################################################################
.PHONY: docs
docs:
	$(MAKE) -C docs && cp docs/dokumentace.pdf .


.PHONY: clean
clean:
	$(RM) dns_$(SENDER) dns_$(RECEIVER) xlapes02.zip dokumentace.pdf
	$(RM) -rd *.dSYM .pytest_cache
	$(MAKE) -C docs clean


.PHONY: zip
zip: clean docs clean
	zip -r $(LOGIN).zip sender receiver common Makefile dokumentace.pdf README.md



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

.PHONY: run_sender_localhost
run_sender_localhost: $(SENDER)
	./dns_$(SENDER) -u 127.0.0.1 example.com data/input1.txt ./output1.txt

.PHONY: run_sender_macos
run_sender_macos: $(SENDER)
	./dns_$(SENDER) -u 0.0.0.0 example.com data/input1.txt ./output1.txt
	#./dns_$(SENDER) -u 127.0.0.1 example.com data/input1.txt ./output1.txt

.PHONY: run_receiver
run_receiver: $(RECEIVER)
	./dns_$(RECEIVER) example.com ./data

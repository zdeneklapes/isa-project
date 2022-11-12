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
LDFLAGS=-lm

#SRC_SENDER_FILES := $(wildcard sender/*.c)
#SRC_RECEIVER_FILES := $(wildcard receiver/*.c)
#SRC_MIDDLE_FILES := $(wildcard middleman/*.c)
#SRC_COMMON_FILES := $(wildcard common/*.c)

SRC_SENDER_FILES := sender/dns_sender.c sender/sender_implementation.c sender/dns_sender_events.c
SRC_RECEIVER_FILES :=  receiver/receiver_implementation.c receiver/dns_receiver_events.c receiver/dns_receiver.c
SRC_MIDDLE_FILES := middleman/middleman.c
SRC_COMMON_FILES := common/base32.c common/dns_helper.c common/initializations.c common/argument_parser.c



###############################################################################
###                            PROGRAM COMPILING                            ###
###############################################################################
# Compile all sender and receiver
all: $(SENDER) $(RECEIVER)

.PHONY: $(SENDER)
$(SENDER): $(SRC_SENDER_FILES) $(SRC_COMMON_FILES) $(SRC_MIDDLE_FILES)
	$(CC) $(CFLAGS) $(SRC_SENDER_FILES) $(SRC_COMMON_FILES) $(SRC_MIDDLE_FILES) -o dns_$@ $(LDFLAGS)

.PHONY: $(RECEIVER)
$(RECEIVER): $(SRC_RECEIVER_FILES) $(SRC_COMMON_FILES) $(SRC_MIDDLE_FILES)
	$(CC) $(CFLAGS) $(SRC_RECEIVER_FILES) $(SRC_COMMON_FILES) $(SRC_MIDDLE_FILES) -o dns_$@ $(LDFLAGS)

###############################################################################
###                            		VALGRIND                                ###
###############################################################################
.PHONY: debug_$(SENDER)
debug_sender: # $(SENDER)
	gcc -g -std=gnu99 -Wall -Wextra -Werror -pedantic -O0 sender/dns_sender.c common/dns_helper.c common/argument_parser.c common/initializations.c -o dns_sender -lm

.PHONY: valgrind_$(SENDER)
valgrind_sender: # $(SENDER)
	gcc -g -std=gnu99 -Wall -Wextra -Werror -pedantic -O0 sender/dns_sender.c common/dns_helper.c common/argument_parser.c common/initializations.c -o dns_sender -lm
	valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --verbose ./dns_$(SENDER)

.PHONY: valgrind_$(RECEIVER)
valgrind_receiver: # $(RECEIVER)
	valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --verbose ./dns_$(RECEIVER)

###############################################################################
###                            		OTHERS                                  ###
###############################################################################
.PHONY: docs
docs:
	$(MAKE) -C docs && cp docs/manual.pdf .


.PHONY: clean
clean:
	$(RM) dns_$(SENDER) dns_$(RECEIVER)
	$(RM) manual.pdf
	$(RM) xlapes02.zip xlapes02.tar xlapes02.tar.gz
	$(RM) -rd *.dSYM .pytest_cache
	$(MAKE) -C docs clean


.PHONY: pack
pack: clean docs clean
	tar -cvf $(LOGIN).tar ./common/* ./sender/* ./receiver/* ./middleman/* ./Makefile ./manual.pdf ./README.md

.PHONY: copy_to_eva
copy_to_eva:
	scp $(LOGIN).tar.gz xlapes02@eva.fit.vutbr.cz:/homes/eva/xl/xlapes02



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

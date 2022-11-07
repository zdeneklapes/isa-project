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
	$(CC) $(CFLAGS) $^ -o dns_$@ $(LDFLAGS)

.PHONY: $(RECEIVER)
$(RECEIVER): $(SRC_RECEIVER_FILES) $(SRC_COMMON_FILES)
	$(CC) $(CFLAGS) $^ -o dns_$@ $(LDFLAGS)


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
	$(RM) dns_$(SENDER) dns_$(RECEIVER) xlapes02.zip manual.pdf xlapes02.tar.gz
	$(RM) -rd *.dSYM .pytest_cache
	$(MAKE) -C docs clean


.PHONY: pack
pack: clean docs clean
	tar cvzf $(LOGIN).tar.gz ./common/* ./sender/* ./receiver/* ./Makefile ./manual.pdf ./README.md



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

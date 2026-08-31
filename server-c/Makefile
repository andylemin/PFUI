# PFUI_Firewall, C implementation. Framing layer only so far; see README.md.

CC      ?= cc
CFLAGS  ?= -std=c99 -O2 -Wall -Wextra -Werror -pedantic
CPPFLAGS += -Iinclude
BUILD   := build
VECTORS := ../protocol/vectors/framing.tsv

.PHONY: all test clean

all: $(BUILD)/test_vectors

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/pfui_wire.o: src/pfui_wire.c include/pfui_wire.h | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c src/pfui_wire.c -o $@

$(BUILD)/test_vectors: tests/test_vectors.c $(BUILD)/pfui_wire.o
	$(CC) $(CFLAGS) $(CPPFLAGS) tests/test_vectors.c $(BUILD)/pfui_wire.o -o $@

# Runs the same vectors as protocol/python/tests/test_vectors.py
test: $(BUILD)/test_vectors
	$(BUILD)/test_vectors $(VECTORS)

clean:
	rm -rf $(BUILD)

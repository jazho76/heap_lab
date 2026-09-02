CC      := gcc
CFLAGS  := -g
LDFLAGS := -no-pie
SRC_DIR := src
BIN_DIR := bin
SRCS    := $(wildcard $(SRC_DIR)/*.c)
BINS    := $(patsubst $(SRC_DIR)/%.c,$(BIN_DIR)/%,$(SRCS))

.PHONY: build clean
build: $(BINS)

$(BIN_DIR)/%: $(SRC_DIR)/%.c | $(BIN_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

clean:
	rm -rf $(BIN_DIR)

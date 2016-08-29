CC = gcc
TARGET = rdtool
CFLAGS = -Os -std=c11
SRC = src/rdtool.c
OUT_DIR = out/
MKDIR = mkdir -p
RM = rm -rf

.PHONY:		all clean

all:		$(TARGET)

clean:
		@$(RM) $(OUT_DIR)

$(TARGET):	$(SRC)
		@$(MKDIR) $(OUT_DIR)
		@$(CC) $(CFLAGS) $< -o $(OUT_DIR)$@

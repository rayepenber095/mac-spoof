CC      = gcc
CFLAGS  = -Wall -Wextra -pedantic -O2
TARGET  = mac_spoof
SRC     = mac_spoof.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

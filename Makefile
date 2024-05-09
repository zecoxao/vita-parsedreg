CC = gcc
SOURCES = fixupdreg2.c sha1.c
TARGET = fixupdreg

all:
	$(CC) $(SOURCES) -o $(TARGET)

clean:
	rm $(TARGET)
CC = gcc
SOURCES = fixupdreg.c sha1.c
TARGET = fixupdreg

all:
	$(CC) $(SOURCES) -o $(TARGET)

clean:
	rm $TARGET
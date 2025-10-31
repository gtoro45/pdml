OPT_FLAGS = -O3
CFLAGS = -Wall $(OPT_FLAGS)
DEBUG_FLAGS = -Wall -g $(OPT_FLAGS)

pdml: format.o zeek_csv.o
	gcc $(CFLAGS) -o pdml format.o zeek_csv.o

format.o: format.c zeek_csv.h
	gcc $(CFLAGS) -c format.c

zeek_csv.o: zeek_csv.c zeek_csv.h
	gcc $(CFLAGS) -c zeek_csv.c

debug: CFLAGS = $(DEBUG_FLAGS)
debug: clean pdml
	@echo "Build complete: debugging symbols enabled."

clean:
	rm -f pdml format.o zeek_csv.o
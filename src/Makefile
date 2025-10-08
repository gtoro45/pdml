CFLAGS = -Wall

pdml: format.o zeek_csv.o
	gcc $(CFLAGS) -o pdml format.o zeek_csv.o

format.o: format.c zeek_csv.h
	gcc $(CFLAGS) -c format.c

zeek_csv.o: zeek_csv.c zeek_csv.h
	gcc $(CFLAGS) -c zeek_csv.c

clean:
	rm -f pdml format.o zeek_csv.o
